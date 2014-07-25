#include <test.h>

#include <files_names.h>


static void test_first_file_separator(void)
{
    const char *out;

    char *in = "/tmp/myfile";
    out = FirstFileSeparator(in);
    assert_true(out == in);

    in = "tmp/myfile";
    out = FirstFileSeparator(in);
    assert_true(out == in + 3);

    in = "c:\\tmp\\myfile";
    out = FirstFileSeparator(in);
    assert_true(out == in + 2);

    in = "\\\\my\\windows\\share";
    out = FirstFileSeparator(in);
    assert_true(out == in + 1);

}

static void test_get_parent_directory_copy(void)
{
    char *out;

#ifndef _WIN32

    /* unix, will fail on windows because of IsFileSep */

    out = GetParentDirectoryCopy("/some/path/here");
    assert_string_equal(out, "/some/path");
    free(out);

    out = GetParentDirectoryCopy("/some/path/here/dir/");
    assert_string_equal(out, "/some/path/here/dir");
    free(out);

    out = GetParentDirectoryCopy("/some/path/here/dir/.");
    assert_string_equal(out, "/some/path/here/dir");
    free(out);

    out = GetParentDirectoryCopy("/some");
    assert_string_equal(out, "/");
    free(out);

#else  /* _WIN32 */

    /* windows, will fail on unix because of IsFileSep */

    out = GetParentDirectoryCopy("c:\\some\\path with space\\here and now");
    assert_string_equal(out, "c:\\some\\path with space");
    free(out);

    out = GetParentDirectoryCopy("c:\\some");
    assert_string_equal(out, "c:\\");
    free(out);

    out = GetParentDirectoryCopy("\\\\some\\path");
    assert_string_equal(out, "\\\\some");
    free(out);

    out = GetParentDirectoryCopy("\\\\some");
    assert_string_equal(out, "\\\\");
    free(out);

#endif  /* _WIN32 */
}


int main()
{
    PRINT_TEST_BANNER();
    const UnitTest tests[] =
    {
        unit_test(test_first_file_separator),
        unit_test(test_get_parent_directory_copy)
    };

    return run_tests(tests);
}
