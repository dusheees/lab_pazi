 #include <stdio.h>
 #include <libakrypt.h>
 #include <stdlib.h>
 #include <string.h>

 int main(int argc, char *argv[])
{
    if(argc > 2) {
        if ((strcmp(argv[2], "-args") == 0) && (argc != 5)) {
            printf("Ошибка при вводе аргументов\n"); 
            return 1; 
        } 
    }
    
    FILE *file;
    file = fopen(argv[1], "r"); 
 
    if (file == NULL) { 
        printf("Не удалось открыть файл '%s'\n", argv[1]); 
        return 1; 
    } 
 
    char *plain_data = NULL;
    int index = 0; 
    char ch; 
    
    long length;
    fseek(file, 0, SEEK_END);
    length = ftell(file);
    fseek(file, 0, SEEK_SET);

    plain_data = (char *)malloc(length);
    if (plain_data == NULL){
        fprintf(stderr, "malloc error");
        fclose(file);
        return EXIT_FAILURE;
    }

    while ((ch = fgetc(file)) != EOF && index < length) { 
        plain_data[index] = ch; 
        index++; 
    } 
 
    fclose(file); 

    printf("Считанный текст из файла:%s\n", plain_data); 

  int error = ak_error_ok;
  struct bckey ctx;
  ak_uint8 key[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01,
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38  };
  ak_uint8 iv[8] = { 0x01, 0x02, 0x03, 0x04, 0x11, 0xaa, 0x4e, 0x12 };

  if( ak_libakrypt_create( NULL ) != ak_true ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

    ak_bckey_create_magma( &ctx );
    if (argc > 2) {
        if ((strcmp(argv[2], "-args") == 0) && (argc == 5)) {
            ak_bckey_set_key_from_password( &ctx, argv[2], strlen(argv[2]), argv[3], strlen(argv[3]));
        } else {
            printf("Неизвестные аргументы\n");
        }
    } else {
        ak_bckey_set_key( &ctx, key, 32 );
    } 

    if(( error = ak_bckey_ofb(  &ctx,        
                                plain_data, 
                                plain_data, 
                                length,        
                                iv,         
                                8           
                            )) != ak_error_ok ) goto exlab;

    file = fopen(argv[1], "w");
    if (file == NULL) {
        perror("Ошибка открытия файла для записи");
        fclose(file);
        return 1;
    }

    fprintf(file, plain_data); 
    fclose(file);

    if(( error = ak_bckey_ofb( &ctx, plain_data, plain_data, length, iv, 8 )) != ak_error_ok ) goto exlab;

    exlab: ak_bckey_destroy( &ctx );

    ak_libakrypt_destroy();
    
    return 0;
}
