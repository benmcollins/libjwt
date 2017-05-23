
/*
 * adapted from libb64 by CB
 */

/*
cdecoder.c - c source to a base64 decoding algorithm implementation

This is part of the libb64 project, and has been placed in the public domain.
For details, see http://sourceforge.net/projects/libb64
*/

#include "b64.h"

static inline char
base64_decode_value (char value_in)
{
  static const char   decoding[] =
    { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1,
    -2, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
    47, 48, 49, 50, 51
  };
  static const char   decoding_size = (char) sizeof (decoding);

  value_in -= 43;
  return (value_in < 0 || value_in >= decoding_size) ?
    -1 : decoding[(int) value_in];
}

void
jwt_base64_init_decodestate (base64_decodestate * state_in)
{
  state_in->step = step_a;
  state_in->plainchar = 0;
}

size_t
jwt_base64_decode_block (const char *code_in, size_t length_in,
                     char *plaintext_out, base64_decodestate * state_in)
{
  /*@unused@ */
  const char         *codechar = code_in;
  char               *plainchar = plaintext_out;
  /*@unused@ */
  char                fragment;

  *plainchar = state_in->plainchar;

  switch (state_in->step) {
    while (1) {
  case step_a:
      do {
        if (codechar == code_in + length_in) {
          state_in->step = step_a;
          state_in->plainchar = *plainchar;
          return (size_t) (plainchar - plaintext_out);
        }
        fragment = base64_decode_value (*codechar++);
      } while (fragment < 0);
      *plainchar = (char) ((fragment & 0x03f) << 2);
  case step_b:
      do {
        if (codechar == code_in + length_in) {
          state_in->step = step_b;
          state_in->plainchar = *plainchar;
          return (size_t) (plainchar - plaintext_out);
        }
        fragment = base64_decode_value (*codechar++);
      } while (fragment < 0);
      *plainchar = (char) (*plainchar | ((fragment & 0x030) >> 4));
      ++plainchar;
      *plainchar = (char) ((fragment & 0x00f) << 4);
  case step_c:
      do {
        if (codechar == code_in + length_in) {
          state_in->step = step_c;
          state_in->plainchar = *plainchar;
          return (size_t) (plainchar - plaintext_out);
        }
        fragment = base64_decode_value (*codechar++);
      } while (fragment < 0);
      *plainchar = (char) (*plainchar | ((fragment & 0x03c) >> 2));
      ++plainchar;
      *plainchar = (char) ((fragment & 0x003) << 6);
  case step_d:
      do {
        if (codechar == code_in + length_in) {
          state_in->step = step_d;
          state_in->plainchar = *plainchar;
          return (size_t) (plainchar - plaintext_out);
        }
        fragment = base64_decode_value (*codechar++);
      } while (fragment < 0);
      *plainchar = (char) (*plainchar | (fragment & 0x03f));
      ++plainchar;
    }
  }
  /* control should not reach here */
  return (size_t) (plainchar - plaintext_out);
}
