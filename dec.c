#include <libakrypt.h>

int ak_bckey_re_encrypt_dec(ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size, ak_uint64 w, ak_uint64 s, ak_uint64 v,
                       ak_uint64 l, ak_pointer l_j, ak_pointer l_j_i, ak_uint64 j);


/* ----------------------------------------------------------------------------------------------- */
/*! При вычислении шифртекста сообщения в режиме `DEC` каждый массив данных разбивают на разделы,
	которые в свою очередь разбиваются на секторы, состоящие из q блоков.


    Длины раздела и сектора является параметром алгоритма и должна удовлетворять требованиям, определёнынм
	в соответствующих рекомендациях по стандартизации.


	При шифровании из входных параметров формируются производные из входного ключа ключи разделов,
	из которых реализуются производные ключи для секторов. Сектор делится на q блоков, которыми оперирует 
	блочный шифр, и шифруется на данном ключе сектора.

    @param bkey Контекст ключа алгоритма блочного шифрования,
    используемый для шифрования и порождения цепочки производных ключей.
    @param in Указатель на область памяти, где хранятся входные данные.
    @param out Указатель на область памяти, куда помещаются выходные данные.
    @param size Размер данных (в байтах), для которых вычисляется имитовставка. 
    @param w Количество разделов, на которые делятся входные данные
    @param s Количество секторов в разделе
	@param v Частота смены ключа
    @param l Длина сектора в байтах
	@param l_j Указатель на область памяти, в которой хранятся счётчики для разделов
	@param l_j_i Указатель на область памяти, в которой хранятся счётчики для секторов

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается \ref ak_error_ok (ноль)                                                           */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_encrypt_dec(ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size, ak_uint64 w, ak_uint64 s, ak_uint64 v,
                    ak_uint64 l, ak_pointer l_j, ak_pointer l_j_i) {
    int error = ak_error_ok;
    ak_uint64 *inptr = (ak_uint64 *)in;
    ak_uint64 *outptr = (ak_uint64 *)out;
    ak_uint64 q = l / bkey->bsize;
    struct kdf_state ks;
    struct bckey internalContext;
    ak_uint8 seed[32] = {0};
    ak_uint8 k_j[32] = {0};
    ak_uint8 k_j_i[32] = {0};
    ak_uint64 delta[2] = {0};
    ak_uint128 z0;
    ak_uint128 P;
    ak_uint128 CTR;
    ak_uint32 *l_j_i_ptr_8 = (ak_uint32 *)l_j_i;
    ak_uint32 *l_j_ptr_8 = (ak_uint32 *)l_j;
    ak_uint64 *l_j_i_ptr_16 = (ak_uint64 *)l_j_i;
    ak_uint64 *l_j_ptr_16 = (ak_uint64 *)l_j;

    if((bkey->bsize != 8) &&  (bkey->bsize != 16)) {
        error = ak_error_wrong_block_cipher;
        ak_error_message(error, __func__ , "incorrect block size of block cipher key");
        goto ext;
    }

    if(l_j == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to l_j");
        goto ext;
    }

    if(l_j_i == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to l_j_i");
        goto ext;
    }

    if(in == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to plain text");
        goto ext;
    }

    if(out == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to cipher text");
        goto ext;
    }

    if(l % bkey->bsize != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect sector byte size");
        goto ext;
    }

    if((ak_uint64)(2 << (bkey->bsize / 2)) % q != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect number of blocks in a sector");
        goto ext;
    }

    if((ak_uint64)(2 << (bkey->bsize / 2)) % w != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect number of volumes");
        goto ext;
    }

    if((ak_uint64)(2 << (bkey->bsize / 2)) % s != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect number of sectors in a volume");
        goto ext;
    }

    if(((ak_uint64)2 << (bkey->bsize / 2)) < v * q) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect frequency of changing key_in");
        goto ext;
    }

    switch (bkey->bsize) {
        case 8:
            for(ak_uint64 j = 0; j < w; ++j) {
                for(ak_uint64 i = 0; i < s; ++i) {
                    if ((*l_j_i_ptr_8) + 1 == 0) {
                        inptr -= i;
                        outptr -= i;
                        l_j_i_ptr_8 -= i;

                        ak_bckey_re_encrypt_dec(bkey, inptr, outptr, size, w, s, v, l, l_j_ptr_8, l_j_i_ptr_8, j);
                    }
                    (*l_j_i_ptr_8)++;

                    z0.q[0] = 0;

                    P.q[0] = *l_j_ptr_8;
                    P.q[0] <<= sizeof(P.q[0]) * 8 / 2;
                    P.q[0] = P.q[0] + j;

                    ak_kdf_state_create(&ks, bkey->key.key, bkey->key.key_size, xor_cmac_magma_kdf,
                                        (ak_uint8 *) &P.q[0], sizeof(P.q[0]),
                                        seed, sizeof(seed), (ak_uint8 *) &z0.q[0], sizeof(z0.q[0]), 32768);
                    ak_kdf_state_next(&ks, k_j, sizeof(k_j));

                    z0.q[0] = j;
                    z0.q[0] <<= sizeof(z0.q[0]) * 8 / 2;

                    P.q[0] = (*l_j_i_ptr_8) / v;
                    P.q[0] <<= sizeof(P.q[0]) * 8 / 2;
                    P.q[0] = P.q[0] + i;


                    ak_kdf_state_create(&ks, k_j, sizeof(k_j), xor_cmac_magma_kdf, (ak_uint8 *) &P.q[0],
                                        sizeof(P.q[0]),
                                        seed, sizeof(seed), (ak_uint8 *) &z0.q[0], sizeof(z0.q[0]), 32768);
                    ak_kdf_state_next(&ks, k_j_i, sizeof(k_j_i));

                    for (ak_uint64 t = 0; t < q; ++t) {
                        CTR.q[0] = i;
                        CTR.q[0] <<= sizeof(CTR.q[0]) * 8 / 2;
                        CTR.q[0] = CTR.q[0] + ((*l_j_i_ptr_8) * q + t);

                        if((error = ak_bckey_create_magma(&internalContext)) != ak_error_ok ) {
                            ak_error_message( error, __func__, "incorrect creation of magma secret key" );
                            goto ext;
                        }
                        ak_bckey_set_key(&internalContext, k_j_i, sizeof(k_j_i));
                        internalContext.encrypt(&internalContext.key, (ak_uint8 *) &CTR.q[0], delta);

                        *outptr = *inptr ^ delta[0];
                        inptr++;
                        outptr++;
                    }
                    l_j_i_ptr_8++;
                }
                l_j_ptr_8++;
            }
            break;

            case 16:
                for (ak_uint64 j = 0; j < w; ++j) {
                    for (ak_uint64 i = 0; i < s; ++i) {
                        if ((*l_j_i_ptr_16) + 1 == 0) {
                            inptr -= i;
                            outptr -= i;
                            l_j_i_ptr_16 -= i;

                            ak_bckey_re_encrypt_dec(bkey, inptr, outptr, size, w, s, v, l, l_j_ptr_16,
                                               l_j_i_ptr_16, j);
                        }
                        (*l_j_i_ptr_16)++;

                        P.q[1] = *l_j_ptr_16;
                        P.q[0] = j;

                        ak_kdf_state_create(&ks, bkey->key.key, bkey->key.key_size,
                                            xor_cmac_kuznechik_kdf, (ak_uint8 *) &P, sizeof(ak_uint128),
                                            seed, sizeof(seed), (ak_uint8 *) &z0, sizeof(ak_uint128),
                                            32768);
                        ak_kdf_state_next(&ks, k_j, sizeof(k_j));

                        z0.q[1] = j;
                        z0.q[0] = 0;

                        P.q[1] = (*l_j_i_ptr_16) / v;
                        P.q[0] = P.q[0] + i;

                        ak_kdf_state_create(&ks, k_j, sizeof(k_j), xor_cmac_kuznechik_kdf,
                                            (ak_uint8 *) &P, sizeof(ak_uint128),
                                            seed, sizeof(seed), (ak_uint8 *) &z0, sizeof(ak_uint128),
                                            32768);
                        ak_kdf_state_next(&ks, k_j_i, sizeof(k_j_i));

                        for (ak_uint64 t = 0; t < q; ++t) {
                            CTR.q[1] = i;
                            CTR.q[0] = ((*l_j_i_ptr_16) * q + t);

                            if((error = ak_bckey_create_kuznechik(&internalContext)) != ak_error_ok ) {
                                ak_error_message( error, __func__, "incorrect creation of kuznechik secret key" );
                                goto ext;
                            }
                            ak_bckey_set_key(&internalContext, k_j_i, sizeof(k_j_i));
                            internalContext.encrypt(&internalContext.key, (ak_uint8 *) &CTR, delta);

                            *outptr = *inptr ^ delta[0];
                            inptr++;
                            outptr++;

                            *outptr = *inptr ^ delta[1];
                            inptr++;
                            outptr++;
                        }
                        l_j_i_ptr_16++;
                    }
                    l_j_ptr_16++;
                }
                break;
    }

ext:
    return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! При вычислении открытого текста сообщения в режиме `DEC` каждый массив данных разбивают на разделы,
	которые в свою очередь разбиваются на секторы, состоящие из q блоков.


    Длины раздела и сектора является параметром алгоритма и должна удовлетворять требованиям, определёнынм
	в соответствующих рекомендациях по стандартизации.


	При расшифровании из входных параметров формируются производные из входного ключа ключи разделов,
	из которых реализуются производные ключи для секторов. Сектор делится на q блоков, которыми оперирует 
	блочный шифр, и расшифровывается на данном ключе сектора.

    @param bkey Контекст ключа алгоритма блочного шифрования,
    используемый для шифрования и порождения цепочки производных ключей.
    @param in Указатель на область памяти, где хранятся входные данные.
    @param out Указатель на область памяти, куда помещаются выходные данные.
    @param size Размер данных (в байтах), для которых вычисляется имитовставка. 
    @param w Количество разделов, на которые делятся входные данные
    @param s Количество секторов в разделе
	@param v Частота смены ключа
    @param l Длина сектора в байтах
	@param l_j Указатель на область памяти, в которой хранятся счётчики для разделов
	@param l_j_i Указатель на область памяти, в которой хранятся счётчики для секторов

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается \ref ak_error_ok (ноль)                                                           */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_decrypt_dec(ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size, ak_uint64 w, ak_uint64 s, ak_uint64 v,
                    ak_uint64 l, ak_pointer l_j, ak_pointer l_j_i) {
    int error = ak_error_ok;
    ak_uint64 *inptr = (ak_uint64 *)in;
    ak_uint64 *outptr = (ak_uint64 *)out;
    ak_uint64 q = l / bkey->bsize;
    struct kdf_state ks;
    struct bckey internalContext;
    ak_uint8 seed[32] = {0};
    ak_uint8 k_j[32] = {0};
    ak_uint8 k_j_i[32] = {0};
    ak_uint64 delta[2] = {0};
    ak_uint128 z0;
    ak_uint128 P;
    ak_uint128 CTR;
    ak_uint32 *l_j_i_ptr_8 = (ak_uint32 *)l_j_i;
    ak_uint32 *l_j_ptr_8 = (ak_uint32 *)l_j;
    ak_uint64 *l_j_i_ptr_16 = (ak_uint64 *)l_j_i;
    ak_uint64 *l_j_ptr_16 = (ak_uint64 *)l_j;


    if((bkey->bsize != 8) &&  (bkey->bsize != 16)) {
        error = ak_error_wrong_block_cipher;
        ak_error_message(error, __func__ , "incorrect block size of block cipher key");
        goto ext;
    }

    if(l_j == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to l_j");
        goto ext;
    }

    if(l_j_i == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to l_j_i");
        goto ext;
    }

    if(in == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to plain text");
        goto ext;
    }

    if(out == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to cipher text");
        goto ext;
    }

    if(l % bkey->bsize != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect sector byte size");
        goto ext;
    }

    if((ak_uint64)(2 << (bkey->bsize / 2)) % q != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect number of blocks in a sector");
        goto ext;
    }

    if((ak_uint64)(2 << (bkey->bsize / 2)) % w != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect number of volumes");
        goto ext;
    }

    if((ak_uint64)(2 << (bkey->bsize / 2)) % s != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect number of sectors in a volume");
        goto ext;
    }

    if(((ak_uint64)2 << (bkey->bsize / 2)) < v * q) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect frequency of changing key_in");
        goto ext;
    }

    switch (bkey->bsize) {
        case 8:
            for(ak_uint64 j = 0; j < w; ++j) {
                for(ak_uint64 i = 0; i < s; ++i) {
                    P.q[0] = *l_j_ptr_8;
                    P.q[0] <<= sizeof(P.q[0]) * 8 / 2;
                    P.q[0] = P.q[0] + j;

                    ak_kdf_state_create(&ks, bkey->key.key, bkey->key.key_size, xor_cmac_magma_kdf, (ak_uint8 *)&P.q[0],
                                        sizeof(P.q[0]), seed, sizeof(seed), (ak_uint8 *)&z0.q[0], sizeof(z0.q[0]), 32768);
                    ak_kdf_state_next(&ks, k_j, sizeof(k_j));

                    z0.q[0] = j;
                    z0.q[0] <<= sizeof(z0.q[0]) * 8 / 2;

                    P.q[0] = (*l_j_i_ptr_8) / v;
                    P.q[0] <<= sizeof(P.q[0]) * 8 / 2;
                    P.q[0] = P.q[0] + i;

                    ak_kdf_state_create(&ks, k_j, sizeof(k_j), xor_cmac_magma_kdf, (ak_uint8 *)&P.q[0], sizeof(P.q[0]),
                                        seed, sizeof(seed), (ak_uint8 *)&z0.q[0], sizeof(z0.q[0]), 32768);
                    ak_kdf_state_next(&ks, k_j_i, sizeof(k_j_i));

                    for(ak_uint64 t = 0; t < q; ++t) {
                        CTR.q[0] = i;
                        CTR.q[0] <<= sizeof(CTR.q[0]) * 8 / 2;
                        CTR.q[0] = CTR.q[0] + ((*l_j_i_ptr_8) * q + t);

                        if ((error = ak_bckey_create_magma(&internalContext)) != ak_error_ok) {
                            ak_error_message(error, __func__, "incorrect creation of magma secret key");
                            goto ext;
                        }
                        ak_bckey_set_key(&internalContext, k_j_i, sizeof(k_j_i));
                        internalContext.encrypt(&internalContext.key, (ak_uint8 *) &CTR.q[0], delta);

                        *outptr = *inptr ^ delta[0];
                        inptr++;
                        outptr++;
                    }
                    l_j_i_ptr_8++;
                }
                l_j_ptr_8++;
            }
            break;

            case 16:
                for(ak_uint64 j = 0; j < w; ++j) {
                    for(ak_uint64 i = 0; i < s; ++i) {
                        P.q[1] = *l_j_ptr_16;
                        P.q[0] = j;

                        ak_kdf_state_create(&ks, bkey->key.key, bkey->key.key_size, xor_cmac_kuznechik_kdf,
                                            (ak_uint8 *)&P, sizeof(ak_uint128), seed, sizeof(seed), (ak_uint8 *)&z0,
                                            sizeof(ak_uint128), 32768);
                        ak_kdf_state_next(&ks, k_j, sizeof(k_j));
                        z0.q[1] = j;
                        z0.q[0] = 0;

                        P.q[1] = (*l_j_i_ptr_16) / v;
                        P.q[0] = 0;
                        P.q[0] = i;


                        ak_kdf_state_create(&ks, k_j, sizeof(k_j), xor_cmac_kuznechik_kdf, (ak_uint8 *)&P,
                                            sizeof(ak_uint128), seed, sizeof(seed), (ak_uint8 *)&z0, sizeof(ak_uint128),
                                            32768);
                        ak_kdf_state_next(&ks, k_j_i, sizeof(k_j_i));

                        for(ak_uint64 t = 0; t < q; ++t) {
                            CTR.q[1] = i;
                            CTR.q[0] = ((*l_j_i_ptr_16) * q + t);

                            if((error = ak_bckey_create_kuznechik(&internalContext)) != ak_error_ok ) {
                                ak_error_message( error, __func__, "incorrect creation of kuznechik secret key" );
                                goto ext;
                            }
                            ak_bckey_set_key(&internalContext, k_j_i, sizeof(k_j_i));
                            internalContext.encrypt(&internalContext.key, (ak_uint8 *)&CTR, delta);

                            *outptr = *inptr ^ delta[0];
                            inptr++;
                            outptr++;
                            *outptr = *inptr ^ delta[1];
                            inptr++;
                            outptr++;
                        }
                        l_j_i_ptr_16++;
                    }
                    l_j_ptr_16++;
                }
                break;
    }

ext:
    return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! При перешифровании сообщения в режиме `DEC` каждый массив данных разбивают на разделы,
	которые в свою очередь разбиваются на секторы, состоящие из q блоков.


    Длины раздела и сектора является параметром алгоритма и должна удовлетворять требованиям, определёнынм
	в соответствующих рекомендациях по стандартизации.


	При перешифровании из входных параметров формируются производные из входного ключа ключи разделов,
	из которых реализуются производные ключи для секторов. Сектор делится на q блоков, которыми оперирует 
	блочный шифр, и расшифровывается на данном ключе сектора.

	Перешифрование применяется к конкретному разделу входных данных

    @param bkey Контекст ключа алгоритма блочного шифрования,
    используемый для шифрования и порождения цепочки производных ключей.
    @param in Указатель на область памяти, где хранятся входные данные.
    @param out Указатель на область памяти, куда помещаются выходные данные.
    @param size Размер данных (в байтах), для которых вычисляется имитовставка. 
    @param w Количество разделов, на которые делятся входные данные
    @param s Количество секторов в разделе
	@param v Частота смены ключа
    @param l Длина сектора в байтах
	@param l_j Указатель на область памяти, в которой хранятся счётчики для разделов
	@param l_j_i Указатель на область памяти, в которой хранятся счётчики для секторов

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается \ref ak_error_ok (ноль)                                                           */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_re_encrypt_dec(ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size, ak_uint64 w, ak_uint64 s, ak_uint64 v,
                       ak_uint64 l, ak_pointer l_j, ak_pointer l_j_i, ak_uint64 j) {
    int error = ak_error_ok;
    ak_uint64 *inptr = (ak_uint64 *)in;
    ak_uint64 *outptr = (ak_uint64 *)out;
    ak_uint64 q = l / bkey->bsize;
    struct kdf_state ks;
    struct bckey internalContext;
    ak_uint8 seed[32] = {0};
    ak_uint8 k_j[32] = {0};
    ak_uint8 k_j_i[32] = {0};
    ak_uint8 k_j_sh[32] = {0};
    ak_uint8 k_j_i_sh[32] = {0};
    ak_uint128 z0;
    ak_uint128 P;
    ak_uint128 CTR;
    ak_uint128 CTR_sh;
    ak_uint64 delta[2];
    ak_uint64 delta_sh[2];
    ak_uint32 *l_j_i_ptr_8 = (ak_uint32 *)l_j_i;
    ak_uint32 *l_j_ptr_8 = (ak_uint32 *)l_j;
    ak_uint32 l_j_i_old_8 = 0;
    ak_uint64 *l_j_i_ptr_16 = (ak_uint64 *)l_j_i;
    ak_uint64 *l_j_ptr_16 = (ak_uint64 *)l_j;
    ak_uint64 l_j_i_old_16 = 0;


    if((bkey->bsize != 8) &&  (bkey->bsize != 16)) {
        error = ak_error_wrong_block_cipher;
        ak_error_message(error, __func__ , "incorrect block size of block cipher key");
        goto ext;
    }

    if(l_j == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to l_j");
        goto ext;
    }

    if(l_j_i == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to l_j_i");
        goto ext;
    }

    if(in == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to plain text");
        goto ext;
    }

    if(out == NULL) {
        error = ak_error_null_pointer;
        ak_error_message(error, __func__, "incorrect pointer to cipher text");
        goto ext;
    }

    if(l % bkey->bsize != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect sector byte size");
        goto ext;
    }

    if((ak_uint64)(2 << (bkey->bsize / 2)) % q != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect number of blocks in a sector");
        goto ext;
    }

    if((ak_uint64)(2 << (bkey->bsize / 2)) % w != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect number of volumes");
        goto ext;
    }

    if((ak_uint64)(2 << (bkey->bsize / 2)) % s != 0) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect number of sectors in a volume");
        goto ext;
    }

    if(((ak_uint64)2 << (bkey->bsize / 2)) < v * q) {
        error = ak_error_wrong_length;
        ak_error_message(error, __func__, "incorrect frequency of changing key_in");
        goto ext;
    }

  
    switch (bkey->bsize) {
        case 8:
            if ((*l_j_ptr_8) + 1 == 0) {
                error = ak_error_wrong_key_icode;
                ak_error_message(error, __func__, "Key_in is can not be used anymore");
                goto ext;
            }
            z0.q[0] = 0;
            P.q[0] = *l_j_ptr_8;
            P.q[0] <<= sizeof(P.q[0]) * 8 / 2;
            P.q[0] = P.q[0] + j;

            ak_kdf_state_create(&ks, bkey->key.key, bkey->key.key_size, xor_cmac_magma_kdf, (ak_uint8 *)&P.q[0],
                                sizeof(P.q[0]), seed, sizeof(seed), (ak_uint8 *)&z0.q[0], sizeof(z0.q[0]), 32768);
            ak_kdf_state_next(&ks, k_j, sizeof(k_j));
            for(ak_uint64 i = 0; i < s; ++i) {
                z0.q[0] = j;
                z0.q[0] <<= sizeof(z0.q[0]) * 8 / 2;

                P.q[0] = (*l_j_i_ptr_8) / v;
                P.q[0] <<= sizeof(P.q[0]) * 8 / 2;
                P.q[0] = P.q[0] + i;

                ak_kdf_state_create(&ks, k_j, sizeof(k_j), xor_cmac_magma_kdf, (ak_uint8 *)&P.q[0], sizeof(P.q[0]),
                                    seed, sizeof(seed), (ak_uint8 *)&z0.q[0], sizeof(z0.q[0]), 32768);
                ak_kdf_state_next(&ks, k_j_i, sizeof(k_j_i));

                z0.q[0] = 0;

                P.q[0] = (*l_j_ptr_8) + 1;
                P.q[0] <<= sizeof(P.q[0]) * 8 / 2;
                P.q[0] = P.q[0] + j;

                ak_kdf_state_create(&ks, bkey->key.key, bkey->key.key_size, xor_cmac_magma_kdf, (ak_uint8 *)&P.q[0],
                                    sizeof(P.q[0]), seed, sizeof(seed), (ak_uint8 *)&z0.q[0], sizeof(z0.q[0]), 32768);
                ak_kdf_state_next(&ks, k_j_sh, sizeof(k_j_sh));

                l_j_i_old_8 = *l_j_i_ptr_8;
                *l_j_i_ptr_8 = 0;

                z0.q[0] = 0;
                z0.q[0] = j;
                z0.q[0] <<= sizeof(z0.q[0]) * 8 / 2;

                P.q[0] = (*l_j_i_ptr_8) / v;
                P.q[0] <<= sizeof(P.q[0]) * 8 / 2;
                P.q[0] = P.q[0] + i;

                ak_kdf_state_create(&ks, k_j_sh, sizeof(k_j_sh), xor_cmac_magma_kdf, (ak_uint8 *)&P.q[0], sizeof(P.q[0]),
                                    seed, sizeof(seed), (ak_uint8 *)&z0.q[0], sizeof(z0.q[0]), 32768);
                ak_kdf_state_next(&ks, k_j_i_sh, sizeof(k_j_i_sh));

                for(ak_uint64 t = 0; t < q; ++t) {
                    CTR.q[0] = i;
                    CTR.q[0] <<= sizeof(CTR.q[0]) * 8 / 2;
                    CTR.q[0] = CTR.q[0] + (l_j_i_old_8 * q + t);

                    if((error = ak_bckey_create_magma(&internalContext)) != ak_error_ok ) {
                        ak_error_message( error, __func__, "incorrect creation of magma secret key" );
                        goto ext;
                    }
                    ak_bckey_set_key(&internalContext, k_j_i, sizeof(k_j_i));
                    internalContext.encrypt(&internalContext.key, (ak_uint8 *)&CTR.q[0], delta);
                    ak_bckey_destroy(&internalContext);

                    CTR_sh.q[0] = i;
                    CTR_sh.q[0] <<= sizeof(CTR_sh.q[0]) * 8 / 2;
                    CTR_sh.q[0] = CTR_sh.q[0] + ((*l_j_i_ptr_8) * q + t);

                    if((error = ak_bckey_create_magma(&internalContext)) != ak_error_ok ) {
                        ak_error_message( error, __func__, "incorrect creation of magma secret key" );
                        goto ext;
                    }
                    ak_bckey_set_key(&internalContext, k_j_i_sh, sizeof(k_j_i_sh));
                    internalContext.encrypt(&internalContext.key, (ak_uint8 *)&CTR_sh.q[0], delta_sh);
                    ak_bckey_destroy(&internalContext);

                    *outptr = *inptr ^ delta_sh[0] ^ delta[0];
                    inptr++;
                    outptr++;
                }
                l_j_i_ptr_8++;
            }

            (*l_j_ptr_8)++;
            break;

        case 16:
            if ((*l_j_ptr_16) + 1 == 0) {
                ak_error_message( error, __func__, "Further utilization of secret key Kin is impossible" );
                goto ext;
            }
            z0.q[0] = 0;
            z0.q[1] = 0;
            P.q[1] = *l_j_ptr_16;
            P.q[0] = j;

            ak_kdf_state_create(&ks, bkey->key.key, bkey->key.key_size, xor_cmac_kuznechik_kdf, (ak_uint8 *)&P,
                                sizeof(ak_uint128), seed, sizeof(seed), (ak_uint8 *)&z0, sizeof(ak_uint128), 32768);
            ak_kdf_state_next(&ks, k_j, sizeof(k_j));
            for(ak_uint64 i = 0; i < s; ++i) {
                z0.q[1] = j;

                P.q[1] = (*l_j_i_ptr_16) / v;
                P.q[0] = i;

                ak_kdf_state_create(&ks, k_j, sizeof(k_j), xor_cmac_kuznechik_kdf, (ak_uint8 *)&P, sizeof(ak_uint128),
                                    seed, sizeof(seed), (ak_uint8 *)&z0, sizeof(ak_uint128), 32768);
                ak_kdf_state_next(&ks, k_j_i, sizeof(k_j_i));

                z0.q[0] = 0;
                z0.q[1] = 0;

                P.q[1] = (*l_j_ptr_16) + 1;
                P.q[0] = j;

                ak_kdf_state_create(&ks, bkey->key.key, bkey->key.key_size, xor_cmac_kuznechik_kdf, (ak_uint8 *)&P,
                                    sizeof(ak_uint128), seed, sizeof(seed), (ak_uint8 *)&z0, sizeof(ak_uint128), 32768);
                ak_kdf_state_next(&ks, k_j_sh, sizeof(k_j_sh));

                l_j_i_old_16 = *l_j_i_ptr_16;
                *l_j_i_ptr_16 = 0;

                z0.q[0] = 0;
                z0.q[1] = j;

                P.q[1] = (*l_j_i_ptr_16) / v;
                P.q[0] = i;

                ak_kdf_state_create(&ks, k_j_sh, sizeof(k_j_sh), xor_cmac_kuznechik_kdf, (ak_uint8 *)&P,
                                    sizeof(ak_uint128), seed, sizeof(seed), (ak_uint8 *)&z0, sizeof(ak_uint128), 32768);
                ak_kdf_state_next(&ks, k_j_i_sh, sizeof(k_j_i_sh));

                for(ak_uint64 t = 0; t < q; ++t) {
                    CTR.q[1] = i;
                    CTR.q[0] = CTR.q[0] + (l_j_i_old_16 * q + t);

                    if((error = ak_bckey_create_kuznechik(&internalContext)) != ak_error_ok ) {
                        ak_error_message( error, __func__, "incorrect creation of kuznechik secret key" );
                        goto ext;
                    }
                    ak_bckey_set_key(&internalContext, k_j_i, sizeof(k_j_i));
                    internalContext.encrypt(&internalContext.key, (ak_uint8 *)&CTR, delta);
                    ak_bckey_destroy(&internalContext);

                    CTR_sh.q[1] = i;
                    CTR_sh.q[0] = CTR_sh.q[0] + ((*l_j_i_ptr_16) * q + t);

                    if((error = ak_bckey_create_kuznechik(&internalContext)) != ak_error_ok ) {
                        ak_error_message( error, __func__, "incorrect creation of kuznechik secret key" );
                        goto ext;
                    }
                    ak_bckey_set_key(&internalContext, k_j_i_sh, sizeof(k_j_i_sh));
                    internalContext.encrypt(&internalContext.key, (ak_uint8 *)&CTR_sh, delta_sh);
                    ak_bckey_destroy(&internalContext);

                    *outptr = *inptr ^ delta_sh[0] ^ delta[0];
                    inptr++;
                    outptr++;
                    *outptr = *inptr ^ delta_sh[1] ^ delta[1];
                    inptr++;
                    outptr++;
                }
                l_j_i_ptr_16++;
            }

            (*l_j_ptr_16)++;
            break;
    }

ext:
    return error;
}


bool_t ak_libakrypt_test_dec() {
    struct bckey key;
    int error = ak_error_ok, audit = ak_log_get_level();
    ak_uint8 skey[32] = {
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54,
            0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 0x55, 0x44, 0x33,
            0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
            0x88};


    ak_uint8 in[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                       0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x10, 0x11, 0x12, 0x13,
                       0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                       0x1d, 0x1e, 0x20, 0x21, 0x22};

    ak_uint8 in2[64] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                       0x0b, 0x0c, 0x0d, 0x0e, 0x10, 0x11, 0x12, 0x13, 0x14,
                       0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                       0x1e, 0x20, 0x21, 0x22, 0x01, 0x02, 0x03, 0x04, 0x05,
                       0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x20, 0x21, 0x22};
    ak_uint8 out[32], out2[64];
    ak_uint8 out_dec[32], out2_dec[64];

    ak_uint32 l_j[2];
    ak_uint32 l_j_i[4];

    ak_uint64 l_j2[1];
    ak_uint64 l_j_i2[2];

    memset(l_j, 0, sizeof(l_j));
    memset(l_j_i, 0, sizeof(l_j_i));


    if((error = ak_bckey_create_magma(&key)) != ak_error_ok) {
        ak_error_message(error, __func__, "incorrect creation of magma secret key");
        return ak_false;
    }
    if((error = ak_bckey_set_key(&key, skey, sizeof(skey))) != ak_error_ok) {
        ak_error_message(error, __func__, "incorrect assigning a key value");
        goto ex1;
    }

    ak_bckey_encrypt_dec(&key, in, out, 32, 1, 2, 3, 16, l_j, l_j_i);
    ak_bckey_decrypt_dec(&key, out, out_dec, 32, 1, 2, 3, 16, l_j, l_j_i);

    if(memcmp(in, out_dec, sizeof(out_dec)) != 0) {
        ak_error_message(error = ak_error_not_equal_data, __func__,
                         "incorrect data comparison after dec encryption with magma cipher");
        goto ex1;
    }

    if(audit >= ak_log_maximum) {
        ak_error_message(ak_error_ok, __func__, "dec test for magma is Ok");
    }
ex1:
    ak_bckey_destroy(&key);

    if(error != ak_error_ok) {
        ak_error_message(ak_error_ok, __func__ , "dec mode test for magma is wrong");
        return ak_false;
    }

    if((error = ak_bckey_create_kuznechik(&key)) != ak_error_ok) {
        ak_error_message(error, __func__, "incorrect creation of kuznechik secret key");
        return ak_false;
    }
    if((error = ak_bckey_set_key(&key, skey, sizeof(skey))) != ak_error_ok) {
        ak_error_message(error, __func__, "incorrect assigning a key value");
        goto ex2;
    }

    ak_bckey_encrypt_dec(&key, in2, out2, 64, 1, 2, 3, 32, l_j2, l_j_i2);
    ak_bckey_decrypt_dec(&key, out2, out2_dec, 64, 1, 2, 3, 32, l_j2, l_j_i2);

    if(memcmp(in2, out2_dec, sizeof(out2_dec)) != 0) {
        ak_error_message(error = ak_error_not_equal_data, __func__,
                         "incorrect data comparison after dec encryption with kuznechik cipher");
        goto ex2;
    }

    if(audit >= ak_log_maximum) {
        ak_error_message(ak_error_ok, __func__, "dec test for kuznechik is Ok");
    }

    if((error = ak_bckey_create_magma(&key)) != ak_error_ok) {
        ak_error_message(error, __func__, "incorrect creation of magma secret key");
        return ak_false;
    }
    if((error = ak_bckey_set_key(&key, skey, sizeof(skey))) != ak_error_ok) {
        ak_error_message(error, __func__, "incorrect assigning a key value");
        goto ex1;
    }

    ak_bckey_re_encrypt_dec(&key, in, out, 32, 1, 2, 3, 16, l_j, l_j_i, 0);
    ak_bckey_decrypt_dec(&key, out, out_dec, 32, 1, 2, 3, 16, l_j, l_j_i);
    if(memcmp(in, out_dec, sizeof(out_dec)) == 0) {
        ak_error_message(error = ak_error_not_equal_data, __func__,
                         "incorrect data comparison after dec encryption with magma cipher");
        goto ex1;
    }

ex2:
    ak_bckey_destroy(&key);

    if(error != ak_error_ok) {
        ak_error_message(ak_error_ok, __func__ , "dec mode test for kuznechik is wrong");
        return ak_false;
    }

    return ak_true;
}
