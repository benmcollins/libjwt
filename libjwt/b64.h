
/*
 * adapted from libb64 by CB
 */

#include <stdlib.h>

/*
cdecode.h - c header for a base64 decoding algorithm

This is part of the libb64 project, and has been placed in the public domain.
For details, see http://sourceforge.net/projects/libb64
*/

#ifndef BASE64_CDECODE_H
#define BASE64_CDECODE_H

#ifdef __cplusplus
extern              "C"
{
#if 0
}
#endif
#endif

typedef enum
{
  step_a, step_b, step_c, step_d
}
base64_decodestep;

typedef struct
{
  base64_decodestep   step;
  char                plainchar;
}
base64_decodestate;

/** This function needs to be called to initialize the internal decoder state.
 * Does not allocate any memory so no cleanup function is necessary after use.
 * \param [out] state_in        Internal state of decoder.
 */
void                jwt_base64_init_decodestate (base64_decodestate * state_in);

/** Decode a chunk of data.
 * This function can be called multiple times for the same state_in.
 * \param [in] code_in          Data in base64 encoding.
 * \param [in] length_in        Length of code_in in bytes.
 * \param [out] plaintext_out   Memory of at least length_in bytes that will
 *                              contain the plaintext on output.
 * \param [in,out] state_in     Internal state of decoder.
 * \return                      Byte length of decoded data in plaintext_out.
 */
size_t              jwt_base64_decode_block (const char *code_in,
                                         size_t length_in,
                                         char *plaintext_out,
                                         base64_decodestate * state_in);

#ifdef __cplusplus
#if 0
{
#endif
}
#endif

#endif /* BASE64_CDECODE_H */

/*
cencode.h - c header for a base64 encoding algorithm

This is part of the libb64 project, and has been placed in the public domain.
For details, see http://sourceforge.net/projects/libb64
*/

#ifndef BASE64_CENCODE_H
#define BASE64_CENCODE_H

#ifdef __cplusplus
extern              "C"
{
#if 0
}
#endif
#endif

typedef enum
{
  step_A, step_B, step_C
}
base64_encodestep;

typedef struct
{
  base64_encodestep   step;
  char                result;
}
base64_encodestate;

/** This function needs to be called to initialize the internal encoder state.
 * Does not allocate any memory so no cleanup function is necessary after use.
 * \param [out] state_in        Internal state of encoder.
 */
void                jwt_base64_init_encodestate (base64_encodestate * state_in);

/** Encode a chunk of data.
 * This function can be called multiple times for the same state_in.
 * \param [in] plaintext_in     Data to be base64 encoded.
 * \param [in] length_in        Length of plaintext_in in bytes.
 * \param [out] code_out        Memory of at least 2 * length_in that will
 *                              contain the base64 encoded data on output.
 * \param [in,out] state_in     Internal state of encoder.
 * \return                      Byte length of encoded data in code_out.
 */
size_t              jwt_base64_encode_block (const char *plaintext_in,
                                         size_t length_in, char *code_out,
                                         base64_encodestate * state_in);

/** Flush remaining code bytes after all input data have been encoded.
 * Must be called when the encoding is done to create valid base64 data.
 * \param [out] code_out        Memory of at least 4 bytes that will contain
 *                              the final encoded bits.
 * \param [in,out] state_in     Internal state of encoder.
 *                              Needs base64_init_encodestate to be used again.
 * \return                      Number of final bytes written to code_out.
 */
size_t              jwt_base64_encode_blockend (char *code_out,
                                            base64_encodestate * state_in);

#ifdef __cplusplus
#if 0
{
#endif
}
#endif

#endif /* BASE64_CENCODE_H */
