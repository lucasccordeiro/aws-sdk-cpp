/**
 * J-1, as a property: can the printer hand JsonView a null pointer?
 *
 *   cJSON.cpp:397-402       parse_number keeps the wire literal, whatever its
 *                           length, whenever the number has no decimal point and
 *                           falls outside [INT_MIN, INT_MAX]
 *   cJSON.cpp:613,645-646   print_number prints that literal through a 26-byte
 *                           buffer and fails the whole document when it does not
 *                           fit; the failure propagates out of PrintUnformatted
 *                           as NULL
 *   JsonSerializer.cpp:680  auto temp = cJSON_AS4CPP_PrintUnformatted(m_value);
 *   JsonSerializer.cpp:681  Aws::String out(temp);   <- N3337 21.4.2/10 requires
 *                           temp not to be a null pointer
 *   JsonSerializer.cpp:697-698, Document.cpp:655-656 and :668-669
 *                           the same pair, three more times
 *
 * The literal's length is the free variable. Nothing here tells ESBMC that 26 is
 * the boundary -- it is asked whether a length exists that makes the printer
 * return null, and the counterexample names one.
 *
 * Why print_number is transcribed rather than linked. ESBMC 8.5.0 will not
 * finish on the vendored cJSON.cpp: its memset/memcpy models unwind once per
 * byte, so the 256-byte print buffer alone puts the run past any bound we could
 * wait for (measured: no verdict in 110 s at --unwind 32, 40 or 70). Passing
 * cJSON.cpp as a *second* C++ translation unit is worse than slow -- the
 * frontend drops its function bodies without a diagnostic, and a call to
 * cJSON_AS4CPP_Parse then returns nondeterministically, so every property
 * "fails" for a reason that has nothing to do with the code. REPORT.md records
 * both. The branch below is print_number's literal arm as it stands in the
 * vendored file, with snprintf's call replaced by the value C11 7.21.6.5p3
 * defines it to return -- the number of characters it would have written --
 * because ESBMC's snprintf model does not return that.
 */

#include <string.h>

extern "C" int nondet_int(void);

/* The longest literal considered. A response body can carry more; the bound only
 * has to reach past the printer's, which is what the counterexample needs. */
#define MAX_LITERAL 40

/* cJSON.cpp:613-646, the arm taken when parse_number kept a literal. */
static bool print_number_succeeds(const char *valuestring)
{
    unsigned char number_buffer[26] = {0};
    const int length = (int)strlen(valuestring); /* = snprintf(number_buffer, sizeof(number_buffer), "%s", valuestring) */

#ifdef FIXED
    /* The patch drops the 26-byte buffer from this arm and copies the literal
     * straight into the output buffer, which ensure() grows for it:
     *
     *   const size_t literal_length = strlen(item->valuestring);
     *   output_pointer = ensure(output_buffer, literal_length + sizeof(""));
     *   if (output_pointer == NULL) { return false; }
     *
     * ensure() fails on the literal's length only at INT_MAX, which it tests
     * twice: on the requested size (cJSON.cpp:517-521) and again after adding
     * the buffer's offset (:534-543). The guard below stands for both. Its
     * remaining failures are allocation and a corrupt printbuffer, neither of
     * which depends on the literal, and neither is what J-1 is about.
     *
     * The row therefore has content in the same shape the pristine one does:
     * the property fails if some length in range makes the printer return null,
     * and it holds only because INT_MAX is not such a length. Shrinking this
     * guard the way `-D BOUNDED` shrinks the buffer breaks it. */
    (void)number_buffer;
    (void)length;
    if ((size_t)strlen(valuestring) + 1u > 2147483647u)
    {
        return false;
    }
    return true;
#else
    /* "snprintf failed or buffer overrun occurred" */
    if ((length < 0) || (length > (int)(sizeof(number_buffer) - 1)))
    {
        return false; /* -> print_value -> print_object -> PrintUnformatted returns NULL */
    }
    return true;
#endif
}

int main()
{
    int n = nondet_int();
    __ESBMC_assume(n >= 1 && n <= MAX_LITERAL);
#ifdef BOUNDED
    /* The other side of the boundary. Without this row the suite would pin only
     * that some length fails, and a printer that rejected every literal would
     * satisfy it just as well. */
    __ESBMC_assume(n <= 25);
#endif

    char valuestring[MAX_LITERAL + 1];
    for (int i = 0; i < n; i++)
    {
        valuestring[i] = '9';
    }
    valuestring[n] = '\0';

    const char *printed = print_number_succeeds(valuestring) ? valuestring : (const char *)0;

    __ESBMC_assert(printed != 0, "the pointer handed to Aws::String is not null");
    return 0;
}
