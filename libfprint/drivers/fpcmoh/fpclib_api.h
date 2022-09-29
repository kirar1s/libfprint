#ifndef __FPCLIB_API_H__
#define __FPCLIB_API_H__

#include <stdint.h>
#include <stdbool.h>

typedef enum fpc_enclave_status {
  FPC_ENCLAVE_ACTIVE,
  FPC_ENCLAVE_LOST
} fpc_enclave_status_t;

enum {
  FPC_TLS_IN_PROGRESS,
  FPC_TLS_HANDSHAKE_COMPLETE
};
typedef int                fpc_tls_status_t;

typedef struct fpc_enclave fpc_enclave_t;

fpc_enclave_t *fpc_create_enclave (void);
int32_t fpc_destroy_enclave (fpc_enclave_t *enclave);
//
int32_t fpc_start_enclave (fpc_enclave_t *enclave);
int32_t fpc_shutdown_enclave (fpc_enclave_t *enclave);
//
int32_t fpc_enclave_init (fpc_enclave_t *enclave,
                          uint16_t       hwid);
int32_t fpc_enclave_handle_tls_connection (fpc_enclave_t *enclave,
                                           uint8_t       *sealed_tls_key,
                                           uint32_t       sealed_tls_key_len);
int32_t fpc_enclave_tls_init_handshake (fpc_enclave_t *enclave);
int32_t fpc_enclave_get_tls_status (fpc_enclave_t    *enclave,
                                    fpc_tls_status_t *status);
int32_t fpc_enclave_get_status (fpc_enclave_t        *enclave,
                                fpc_enclave_status_t *status);
int32_t fpc_enclave_process_data (fpc_enclave_t *enclave);
int fpc_tls_receive_usb_data (void   * param,
                              uint8_t *data,
                              size_t   len,
                              uint32_t timeout_ms);
int fpc_tls_send_usb_data (void         * param,
                           const uint8_t *data,
                           size_t         len);

int32_t fpc_secure_random (uint8_t * data,
                           uint32_t  data_size);

typedef struct fpc_fifo_struct
{
  uint8_t *buffer;
  uint16_t put_index;
  uint16_t get_index;
  uint32_t is_full;
  uint32_t size;
} fpc_fifo_t;

bool         fpc_fifo_is_empty (fpc_fifo_t *fifo);
void         fpc_fifo_clear (fpc_fifo_t *fifo);
void         fpc_fifo_copy (fpc_fifo_t *dst,
                            fpc_fifo_t *src);
void         fpc_fifo_free (fpc_fifo_t *fifo);
void         fpc_fifo_put (fpc_fifo_t *fifo,
                           uint8_t    *data,
                           uint32_t    len);
uint32_t     fpc_fifo_get (fpc_fifo_t *fifo,
                           uint8_t    *buff,
                           uint32_t    len);
fpc_fifo_t  *fpc_fifo_init (uint32_t size);

#define FPC_CONFIG_MAX_NR_TEMPLATES 10
#define FPC_TA_BIO_DB_RDONLY 0
#define FPC_TA_BIO_DB_WRONLY 1

typedef struct fpc_tac fpc_tac_t;

typedef struct fpc_tac_shared_mem
{
  void * addr;
} fpc_tac_shared_mem_t;

struct fpc_tee
{
  fpc_tac_t            * tac;
  fpc_tac_shared_mem_t * shared_buffer;
};

typedef struct fpc_tee fpc_tee_t;

struct fpc_tee_bio
{
  fpc_tee_t tee;
};

typedef struct fpc_tee_bio fpc_tee_bio_t;

fpc_tee_t *fpc_tee_init (void);
void fpc_tee_release (fpc_tee_t * tee);

/**
 * @brief fpc_tac_open open a connection to the ta.
 * @return the tac or NULL on failure.
 */
fpc_tac_t * fpc_tac_open (void);

/**
 * @brief fpc_tac_release close the connection to the ta.
 */
void fpc_tac_release (fpc_tac_t * tac);

fpc_tee_bio_t * fpc_tee_bio_init (fpc_tee_t * tee);
void fpc_tee_bio_release (fpc_tee_bio_t * tee);

int fpc_tee_set_gid (fpc_tee_bio_t * tee,
                     int32_t         gid);
int fpc_tee_begin_enroll (fpc_tee_bio_t * tee);
int fpc_tee_enroll (fpc_tee_bio_t * tee,
                    uint32_t      * remaining);
int fpc_tee_end_enroll (fpc_tee_bio_t * tee,
                        uint32_t      * id);
int fpc_tee_identify (fpc_tee_bio_t * tee,
                      uint32_t      * id);
int fpc_tee_qualify_image (fpc_tee_bio_t * tee);

int fpc_tee_update_template (fpc_tee_bio_t * tee,
                             uint32_t      * update);
int fpc_tee_get_finger_ids (fpc_tee_bio_t * tee,
                            uint32_t      * size,
                            uint32_t      * ids);
int fpc_tee_delete_template (fpc_tee_bio_t * tee,
                             uint32_t        id);
int fpc_tee_get_template_db_id (fpc_tee_bio_t * tee,
                                uint64_t      * id);

int fpc_tee_load_empty_db (fpc_tee_bio_t * tee);
int fpc_tee_get_db_blob_size (fpc_tee_t * tee,
                              size_t     *blob_size);
int fpc_tee_db_open (fpc_tee_t *tee,
                     uint32_t   mode,
                     uint32_t   size);
int fpc_tee_db_close (fpc_tee_t *tee);
int fpc_tee_send_db_read_commands (fpc_tee_t * tee,
                                   uint8_t    *blob,
                                   size_t      blob_size);
int fpc_tee_send_db_write_commands (fpc_tee_t    * tee,
                                    const uint8_t *blob,
                                    size_t         blob_size);

int fpc_tls_buff_init (void);
int fpc_tls_buff_release (void);
int fpc_tls_buff_clear (void);
int fpc_tls_buff_put (uint8_t *data,
                      uint32_t len);
int fpc_tls_write_buff_init (void);
int fpc_tls_write_buff_release (void);
int fpc_tls_write_buff_clear (void);
uint8_t fpc_tls_write_buff_is_empty (void);
uint32_t fpc_tls_write_buff_get (uint8_t *o_data,
                                 uint32_t len);

#endif // __FPCLIB_API_H__
