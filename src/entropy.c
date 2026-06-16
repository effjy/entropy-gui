/*
 * Entropy (GTK3 GUI)
 * ---------------------------
 * Two tabs:
 *   1. Verify entropy    - naive vs. estimated "real" entropy
 *   2. Generate password - choose length and character classes
 *
 * Entropy notes:
 *   NAIVE (theoretical) = length * log2(charset_size)
 *   REAL  (estimated)   = naive minus penalties for repeats,
 *                         sequences, dictionary words, leet-speak,
 *                         and low character variety.
 *   Spaces count as valid characters.
 *
 * Password generation uses getrandom() (a CSPRNG) with unbiased
 * rejection sampling, so generated passwords are safe for real use.
 *
 * Compile:  make         (uses pkg-config gtk+-3.0)
 * Run:      ./entropy
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <sys/random.h>   /* getrandom() */
#include <errno.h>
#include <limits.h>

#define MAX_PW 256

/* G_APPLICATION_DEFAULT_FLAGS was introduced in GLib 2.74, replacing the
 * now-deprecated G_APPLICATION_FLAGS_NONE. Pick whichever the GLib in use
 * supports so the app builds cleanly on both old and new toolchains. */
#if GLIB_CHECK_VERSION(2, 74, 0)
#  define ENTROPY_APP_FLAGS G_APPLICATION_DEFAULT_FLAGS
#else
#  define ENTROPY_APP_FLAGS G_APPLICATION_FLAGS_NONE
#endif

/* Path to the installed icon (overridden at build time via -DICON_PATH). */
#ifndef ICON_PATH
#define ICON_PATH "entropy.png"
#endif

/* ----- built-in dictionary of common words / passwords ----- */
static const char *DICT[] = {
    "password", "passwd", "admin", "letmein", "welcome", "qwerty",
    "monkey", "dragon", "master", "login", "abc", "iloveyou",
    "sunshine", "princess", "football", "baseball", "shadow",
    "superman", "batman", "trustno", "hello", "world", "secret",
    "summer", "winter", "spring", "autumn", "love", "money",
    "computer", "internet", "google", "michael", "jordan",
    "the", "and", "you", "for", "are", "with", "this", "that",
    "have", "from", "they", "what", "house", "horse", "table",
    "apple", "orange", "banana", "purple", "yellow", "green",
    "happy", "ninja", "rocket", "tiger", "eagle", "ocean",
    NULL
};

/* Zero a buffer in a way the compiler won't optimize away, so sensitive
 * material (passwords) doesn't linger in memory longer than necessary. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

/* ===================== ENTROPY HELPERS ===================== */

static char deleet(char c) {
    switch (tolower((unsigned char)c)) {
        case '0': return 'o';
        case '1': return 'i';
        case '3': return 'e';
        case '4': return 'a';
        case '5': return 's';
        case '7': return 't';
        case '8': return 'b';
        case '@': return 'a';
        case '$': return 's';
        case '!': return 'i';
        default:  return (char)tolower((unsigned char)c);
    }
}

static void normalize(const char *in, char *out, size_t n) {
    size_t i = 0;
    for (; in[i] && i < n - 1; i++)
        out[i] = deleet(in[i]);
    out[i] = '\0';
}

static int charset_size(const char *pw, int *out_classes) {
    int lower = 0, upper = 0, digit = 0, space = 0, symbol = 0;
    for (const char *p = pw; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (islower(c))      lower = 1;
        else if (isupper(c)) upper = 1;
        else if (isdigit(c)) digit = 1;
        else if (c == ' ')   space = 1;
        else if (isgraph(c)) symbol = 1;   /* printable punctuation only */
        /* non-printable bytes contribute no class */
    }
    int size = 0;
    if (lower)  size += 26;
    if (upper)  size += 26;
    if (digit)  size += 10;
    if (space)  size += 1;
    if (symbol) size += 32;

    *out_classes = lower + upper + digit + space + symbol;
    return size ? size : 1;
}

static int repeated_chars(const char *pw) {
    int seen[256] = {0};
    int repeats = 0;
    for (const char *p = pw; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (seen[c]) repeats++;
        seen[c] = 1;
    }
    return repeats;
}

/* A run is "sequential" only when all three characters belong to the same
 * class (all letters or all digits), so cross-class runs like "9:;" or "/0"
 * are not mistaken for sequences. */
static int same_seq_class(unsigned char a, unsigned char b, unsigned char c) {
    if (isalpha(a) && isalpha(b) && isalpha(c)) return 1;
    if (isdigit(a) && isdigit(b) && isdigit(c)) return 1;
    return 0;
}

static int sequential_chars(const char *pw) {
    int seq = 0;
    size_t len = strlen(pw);
    for (size_t i = 2; i < len; i++) {
        unsigned char ra = (unsigned char)pw[i - 2];
        unsigned char rb = (unsigned char)pw[i - 1];
        unsigned char rc = (unsigned char)pw[i];
        if (!same_seq_class(ra, rb, rc)) continue;
        char a = (char)tolower(ra);
        char b = (char)tolower(rb);
        char c = (char)tolower(rc);
        if ((b == a + 1 && c == b + 1) ||
            (b == a - 1 && c == b - 1))
            seq++;
    }
    return seq;
}

static int dictionary_coverage(const char *norm) {
    size_t len = strlen(norm);
    int *covered = calloc(len + 1, sizeof(int));
    if (!covered) return 0;

    for (int d = 0; DICT[d]; d++) {
        const char *w = DICT[d];
        size_t wl = strlen(w);
        if (wl < 3 || wl > len) continue;
        for (size_t i = 0; i + wl <= len; i++) {
            if (strncmp(norm + i, w, wl) == 0) {
                for (size_t k = i; k < i + wl; k++) covered[k] = 1;
            }
        }
    }
    int count = 0;
    for (size_t i = 0; i < len; i++) count += covered[i];
    free(covered);
    return count;
}

static const char *verdict_for(double r) {
    if      (r < 28)  return "Very weak";
    else if (r < 36)  return "Weak";
    else if (r < 60)  return "Reasonable";
    else if (r < 128) return "Strong";
    else              return "Very strong";
}

/* Analyze a password and return a newly-allocated report string.
 * If out_real is non-NULL, the estimated "real" entropy is stored there.
 * Caller frees the returned string with g_free(). */
static char *analyze_report(const char *pw, double *out_real) {
    char norm[MAX_PW];
    size_t len = strlen(pw);
    if (out_real) *out_real = 0.0;
    if (len == 0)
        return g_strdup("Empty password. Entropy = 0 bits.");

    int classes;
    int pool = charset_size(pw, &classes);
    double bits_per_char = log2((double)pool);
    double naive = len * bits_per_char;

    int repeats = repeated_chars(pw);
    int seq     = sequential_chars(pw);
    normalize(pw, norm, sizeof(norm));
    int dict    = dictionary_coverage(norm);

    double penalty = 0.0;
    /* Repeats are penalized, but capped so that a long password drawn from a
     * small pool (which naturally repeats characters) is not driven to zero. */
    double repeat_penalty = repeats * bits_per_char;
    double repeat_cap = naive * 0.5;
    if (repeat_penalty > repeat_cap) repeat_penalty = repeat_cap;
    penalty += repeat_penalty;
    penalty += seq     * bits_per_char * 0.5;
    penalty += dict    * bits_per_char * 0.75;
    if (classes <= 1) penalty += naive * 0.10;

    double real = naive - penalty;
    if (real < 0) real = 0;
    if (out_real) *out_real = real;

    wipe(norm, sizeof(norm));

    return g_strdup_printf(
        "--- Results ---\n"
        "Length              : %zu characters\n"
        "Character pool size : %d\n"
        "Bits per character  : %.2f\n"
        "Repeated chars      : %d\n"
        "Sequential chars    : %d\n"
        "Dictionary chars    : %d\n"
        "\n"
        "NAIVE entropy : %.2f bits\n"
        "REAL  entropy : %.2f bits  (estimate)\n"
        "\n"
        "Strength assessment : %s",
        len, pool, bits_per_char, repeats, seq, dict,
        naive, real, verdict_for(real));
}

/* ===================== GENERATOR ===================== */

static const char *SET_LOWER  = "abcdefghijklmnopqrstuvwxyz";
static const char *SET_UPPER  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *SET_DIGIT  = "0123456789";
/* All 32 ASCII printable punctuation characters, matching the +32 symbol
 * pool credited in charset_size() so generated passwords' reported entropy
 * is consistent with how they were actually produced. */
static const char *SET_SYMBOL = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/* Fill buf with len cryptographically secure random bytes.
 * Returns 0 on success, -1 on failure. Handles short reads and EINTR. */
static int secure_bytes(unsigned char *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t r = getrandom(buf + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;   /* interrupted, retry */
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

/* Return a uniform random value in [0, n) with no modulo bias,
 * using rejection sampling over secure bytes. n must be 1..256.
 * Returns -1 on RNG failure. */
static int secure_index(size_t n) {
    if (n <= 1) return 0;
    /* Largest multiple of n that fits in a byte; reject anything above it. */
    unsigned int limit = 256u - (256u % (unsigned int)n);
    unsigned char b;
    for (;;) {
        if (secure_bytes(&b, 1) != 0)
            return -1;
        if (b < limit) return (int)(b % n);
    }
}

/* Generate a password into out (size MAX_PW). Returns 0 on success,
 * -1 on RNG failure, -2 if no classes selected. */
static int generate_password(int length, int use_lower, int use_upper,
                             int use_digit, int use_symbol, char *out) {
    if (length > MAX_PW - 1) length = MAX_PW - 1;
    if (length <= 0) length = 1;

    /* Collect the selected character sets. */
    const char *sets[4];
    int nsets = 0;
    if (use_lower)  sets[nsets++] = SET_LOWER;
    if (use_upper)  sets[nsets++] = SET_UPPER;
    if (use_digit)  sets[nsets++] = SET_DIGIT;
    if (use_symbol) sets[nsets++] = SET_SYMBOL;
    if (nsets == 0) return -2;

    char pool[256];
    pool[0] = '\0';
    for (int i = 0; i < nsets; i++) strcat(pool, sets[i]);
    size_t pool_len = strlen(pool);

    int rc = 0;

    /* When the length allows, guarantee one character from each selected
     * class by placing them first; fill the rest from the full pool. This
     * removes the old retry-and-hope loop (which could silently return a
     * password missing a class). */
    int guaranteed = (length >= nsets) ? nsets : 0;
    for (int i = 0; i < guaranteed; i++) {
        size_t sl = strlen(sets[i]);
        int idx = secure_index(sl);
        if (idx < 0) { rc = -1; goto done; }
        out[i] = sets[i][idx];
    }
    for (int i = guaranteed; i < length; i++) {
        int idx = secure_index(pool_len);
        if (idx < 0) { rc = -1; goto done; }
        out[i] = pool[idx];
    }
    out[length] = '\0';

    /* Fisher-Yates shuffle so the guaranteed characters aren't predictably
     * at the front. Uses unbiased secure_index for each swap. */
    for (int i = length - 1; i > 0; i--) {
        int j = secure_index((size_t)(i + 1));
        if (j < 0) { rc = -1; goto done; }
        char t = out[i]; out[i] = out[j]; out[j] = t;
    }

done:
    wipe(pool, sizeof(pool));
    return rc;
}

/* ===================== GUI ===================== */

/* A cool, professional dark theme. Teal/cyan accent on a near-black base
 * with a hint of indigo — a "security console" feel. */
static const char *APP_CSS =
    "window { background-color: #0d1117; color: #e6edf3; }"
    "* { font-family: 'Inter', 'Segoe UI', 'Cantarell', sans-serif; }"
    "headerbar { background-image: none;"
    "  background-color: #161b22; border-bottom: 1px solid #21262d;"
    "  box-shadow: none; color: #e6edf3; padding: 4px 8px; }"
    "headerbar button { background-image: none; background-color: transparent;"
    "  color: #9aa4b2; border: none; box-shadow: none; }"
    "headerbar button:hover { background-color: #21262d; color: #2dd4bf; }"
    /* Hero strip */
    ".hero { background-image: none;"
    "  background-color: #0b1220; padding: 16px 18px;"
    "  border-bottom: 1px solid #1f2937; }"
    ".hero-title { font-size: 20px; font-weight: 800; color: #2dd4bf; }"
    ".hero-subtitle { font-size: 11px; color: #7d8590;"
    "  letter-spacing: 1px; }"
    /* Tabs */
    "notebook header { background-color: #0d1117; border: none; }"
    "notebook header tabs tab { color: #7d8590; padding: 8px 18px;"
    "  border: none; background-color: transparent; font-weight: 600; }"
    "notebook header tabs tab:checked { color: #2dd4bf;"
    "  box-shadow: inset 0 -2px 0 #2dd4bf; }"
    "notebook header tabs tab:hover { color: #e6edf3; }"
    /* Section labels */
    ".section-label { color: #9aa4b2; font-weight: 600; }"
    /* Entries */
    "entry { background-color: #0b0f14; color: #e6edf3;"
    "  border: 1px solid #283039; border-radius: 8px; padding: 8px 10px; }"
    "entry:focus { border-color: #2dd4bf;"
    "  box-shadow: 0 0 0 2px rgba(45,212,191,0.20); }"
    ".password-display { font-family: 'JetBrains Mono', monospace;"
    "  font-size: 15px; color: #2dd4bf; letter-spacing: 1px; }"
    /* Buttons */
    "button { border-radius: 8px; padding: 8px 14px; font-weight: 600;"
    "  border: 1px solid #283039; background-image: none;"
    "  background-color: #1b2129; color: #e6edf3; }"
    "button:hover { background-color: #232b35; }"
    ".accent { background-image: none; background-color: #2dd4bf;"
    "  color: #04201c; border: none; }"
    ".accent:hover { background-color: #45e3d0; }"
    ".accent:active { background-color: #1fbfac; }"
    /* Check buttons */
    "checkbutton { color: #c9d1d9; }"
    "checkbutton check { background-color: #0b0f14; border: 1px solid #30363d;"
    "  border-radius: 4px; }"
    "checkbutton check:checked { background-color: #2dd4bf;"
    "  border-color: #2dd4bf; color: #04201c; }"
    /* Spin button */
    "spinbutton { background-color: #0b0f14; border-radius: 8px;"
    "  border: 1px solid #283039; color: #e6edf3; }"
    /* Result text view */
    "textview, textview text { background-color: #0b0f14; color: #c9d1d9;"
    "  font-family: 'JetBrains Mono', monospace; }"
    ".card { background-color: #0b0f14; border: 1px solid #1f2937;"
    "  border-radius: 10px; }"
    /* Strength meter */
    "progressbar trough { min-height: 10px; border-radius: 6px;"
    "  background-color: #161b22; border: none; }"
    "progressbar progress { min-height: 10px; border-radius: 6px; }"
    "progressbar.s-veryweak progress { background-color: #f85149; }"
    "progressbar.s-weak     progress { background-color: #fb923c; }"
    "progressbar.s-ok       progress { background-color: #fbbf24; }"
    "progressbar.s-strong   progress { background-color: #34d399; }"
    "progressbar.s-very     progress { background-color: #2dd4bf; }"
    ".verdict { font-weight: 800; font-size: 13px; }"
    ".verdict.s-veryweak { color: #f85149; }"
    ".verdict.s-weak     { color: #fb923c; }"
    ".verdict.s-ok       { color: #fbbf24; }"
    ".verdict.s-strong   { color: #34d399; }"
    ".verdict.s-very     { color: #2dd4bf; }";

typedef struct {
    GtkWidget *verify_entry;
    GtkWidget *verify_show;
    GtkWidget *verify_result;
    GtkWidget *verify_bar;
    GtkWidget *verify_verdict;

    GtkWidget *gen_length;
    GtkWidget *gen_lower;
    GtkWidget *gen_upper;
    GtkWidget *gen_digit;
    GtkWidget *gen_symbol;
    GtkWidget *gen_output;
    GtkWidget *gen_result;
    GtkWidget *gen_bar;
    GtkWidget *gen_verdict;
} AppWidgets;

static void add_class(GtkWidget *w, const char *cls) {
    gtk_style_context_add_class(gtk_widget_get_style_context(w), cls);
}

static void set_text_view(GtkWidget *view, const char *text) {
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    gtk_text_buffer_set_text(buf, text, -1);
}

/* Map estimated entropy to a strength CSS class. */
static const char *strength_class(double real) {
    if      (real < 28)  return "s-veryweak";
    else if (real < 36)  return "s-weak";
    else if (real < 60)  return "s-ok";
    else if (real < 128) return "s-strong";
    else                 return "s-very";
}

/* Update a progress-bar meter + verdict badge from a real-entropy value. */
static void update_strength(GtkWidget *bar, GtkWidget *verdict, double real) {
    static const char *classes[] = {
        "s-veryweak", "s-weak", "s-ok", "s-strong", "s-very", NULL
    };
    const char *cls = strength_class(real);

    double frac = real / 128.0;
    if (frac > 1.0) frac = 1.0;
    if (frac < 0.0) frac = 0.0;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(bar), frac);

    GtkStyleContext *bc = gtk_widget_get_style_context(bar);
    GtkStyleContext *vc = gtk_widget_get_style_context(verdict);
    for (int i = 0; classes[i]; i++) {
        gtk_style_context_remove_class(bc, classes[i]);
        gtk_style_context_remove_class(vc, classes[i]);
    }
    gtk_style_context_add_class(bc, cls);
    gtk_style_context_add_class(vc, cls);

    char *txt = g_strdup_printf("%s  \xC2\xB7  %.0f bits", verdict_for(real), real);
    gtk_label_set_text(GTK_LABEL(verdict), txt);
    g_free(txt);
}

static void on_verify_clicked(GtkButton *btn, gpointer data) {
    (void)btn;
    AppWidgets *w = data;
    const char *pw = gtk_entry_get_text(GTK_ENTRY(w->verify_entry));
    double real = 0.0;
    char *report = analyze_report(pw, &real);
    set_text_view(w->verify_result, report);
    update_strength(w->verify_bar, w->verify_verdict, real);
    g_free(report);
}

static void on_verify_show_toggled(GtkToggleButton *t, gpointer data) {
    AppWidgets *w = data;
    gtk_entry_set_visibility(GTK_ENTRY(w->verify_entry),
                             gtk_toggle_button_get_active(t));
}

static void on_generate_clicked(GtkButton *btn, gpointer data) {
    (void)btn;
    AppWidgets *w = data;
    int length = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(w->gen_length));
    int use_lower  = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w->gen_lower));
    int use_upper  = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w->gen_upper));
    int use_digit  = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w->gen_digit));
    int use_symbol = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w->gen_symbol));

    char out[MAX_PW];
    int rc = generate_password(length, use_lower, use_upper,
                               use_digit, use_symbol, out);
    if (rc == -2) {
        gtk_entry_set_text(GTK_ENTRY(w->gen_output), "");
        set_text_view(w->gen_result, "No character classes selected.");
        return;
    }
    if (rc == -1) {
        gtk_entry_set_text(GTK_ENTRY(w->gen_output), "");
        set_text_view(w->gen_result,
                      "getrandom() failed; cannot generate securely.");
        return;
    }

    gtk_entry_set_text(GTK_ENTRY(w->gen_output), out);
    double real = 0.0;
    char *report = analyze_report(out, &real);
    set_text_view(w->gen_result, report);
    update_strength(w->gen_bar, w->gen_verdict, real);
    g_free(report);
    wipe(out, sizeof(out));
}

static void on_about_clicked(GtkButton *btn, gpointer data) {
    (void)data;
    GtkWidget *toplevel = gtk_widget_get_toplevel(GTK_WIDGET(btn));
    GtkWindow *parent = GTK_IS_WINDOW(toplevel) ? GTK_WINDOW(toplevel) : NULL;

    GtkWidget *dialog = gtk_about_dialog_new();
    GtkAboutDialog *about = GTK_ABOUT_DIALOG(dialog);
    if (parent)
        gtk_window_set_transient_for(GTK_WINDOW(dialog), parent);

    gtk_about_dialog_set_program_name(about, "Entropy");
    gtk_about_dialog_set_version(about, "1.0");
    gtk_about_dialog_set_comments(about,
        "A GTK3 toolkit for password security.\n\n"
        "Features:\n"
        "  \xE2\x80\xA2 Verify entropy: naive vs. estimated \"real\" entropy\n"
        "  \xE2\x80\xA2 Penalties for repeats, sequences, dictionary words,\n"
        "    leet-speak, and low character variety\n"
        "  \xE2\x80\xA2 Strength assessment with clear verdicts\n"
        "  \xE2\x80\xA2 Generate secure passwords with a CSPRNG (getrandom)\n"
        "  \xE2\x80\xA2 Unbiased rejection sampling, selectable character classes\n"
        "  \xE2\x80\xA2 One-click copy to clipboard");
    gtk_about_dialog_set_copyright(about,
        "\xC2\xA9 2026 Jean-Francois Lachance-Caumartin");

    const char *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
    gtk_about_dialog_set_authors(about, authors);

    /* Logo: try the installed icon file, fall back to the theme name. */
    GError *err = NULL;
    GdkPixbuf *logo = gdk_pixbuf_new_from_file_at_size(ICON_PATH, 128, 128, &err);
    if (logo) {
        gtk_about_dialog_set_logo(about, logo);
        g_object_unref(logo);
    } else {
        g_clear_error(&err);
        gtk_about_dialog_set_logo_icon_name(about, "entropy");
    }

    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void on_copy_clicked(GtkButton *btn, gpointer data) {
    (void)btn;
    AppWidgets *w = data;
    const char *pw = gtk_entry_get_text(GTK_ENTRY(w->gen_output));
    if (pw && *pw) {
        GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
        gtk_clipboard_set_text(cb, pw, -1);
    }
}

static GtkWidget *make_result_view(void) {
    GtkWidget *view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 12);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 12);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(view), 10);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(view), 10);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    add_class(scroll, "card");
    gtk_container_add(GTK_CONTAINER(scroll), view);
    /* Stash the view on the scroll so the caller can fetch it. */
    g_object_set_data(G_OBJECT(scroll), "view", view);
    return scroll;
}

/* A strength meter: a small caption, a color-coded bar, and a verdict badge.
 * The bar and verdict widgets are returned through out-params. */
static GtkWidget *make_strength_meter(GtkWidget **out_bar,
                                      GtkWidget **out_verdict) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);

    GtkWidget *caprow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *caption = gtk_label_new("STRENGTH");
    gtk_widget_set_halign(caption, GTK_ALIGN_START);
    add_class(caption, "section-label");
    gtk_box_pack_start(GTK_BOX(caprow), caption, FALSE, FALSE, 0);

    GtkWidget *verdict = gtk_label_new("\xE2\x80\x94");
    gtk_widget_set_halign(verdict, GTK_ALIGN_END);
    add_class(verdict, "verdict");
    gtk_box_pack_end(GTK_BOX(caprow), verdict, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), caprow, FALSE, FALSE, 0);

    GtkWidget *bar = gtk_progress_bar_new();
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(bar), 0.0);
    gtk_box_pack_start(GTK_BOX(box), bar, FALSE, FALSE, 0);

    *out_bar = bar;
    *out_verdict = verdict;
    return box;
}

static GtkWidget *build_verify_tab(AppWidgets *w) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 18);

    GtkWidget *label = gtk_label_new("PASSWORD TO ANALYZE");
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    add_class(label, "section-label");
    gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);

    w->verify_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(w->verify_entry), FALSE);
    gtk_entry_set_max_length(GTK_ENTRY(w->verify_entry), MAX_PW - 1);
    gtk_entry_set_placeholder_text(GTK_ENTRY(w->verify_entry),
                                   "Type or paste a password (spaces allowed)\xE2\x80\xA6");
    gtk_box_pack_start(GTK_BOX(box), w->verify_entry, FALSE, FALSE, 0);

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    w->verify_show = gtk_check_button_new_with_label("Show password");
    g_signal_connect(w->verify_show, "toggled",
                     G_CALLBACK(on_verify_show_toggled), w);
    gtk_box_pack_start(GTK_BOX(row), w->verify_show, FALSE, FALSE, 0);

    GtkWidget *verify_btn = gtk_button_new_with_label("Analyze");
    add_class(verify_btn, "accent");
    g_signal_connect(verify_btn, "clicked",
                     G_CALLBACK(on_verify_clicked), w);
    gtk_box_pack_end(GTK_BOX(row), verify_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 0);

    /* Verify on Enter too. */
    g_signal_connect(w->verify_entry, "activate",
                     G_CALLBACK(on_verify_clicked), w);

    GtkWidget *meter = make_strength_meter(&w->verify_bar, &w->verify_verdict);
    gtk_box_pack_start(GTK_BOX(box), meter, FALSE, FALSE, 0);

    GtkWidget *scroll = make_result_view();
    w->verify_result = g_object_get_data(G_OBJECT(scroll), "view");
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);

    return box;
}

static GtkWidget *build_generate_tab(AppWidgets *w) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(box), 18);

    GtkWidget *lenrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *lenlbl = gtk_label_new("LENGTH");
    add_class(lenlbl, "section-label");
    gtk_box_pack_start(GTK_BOX(lenrow), lenlbl, FALSE, FALSE, 0);
    w->gen_length = gtk_spin_button_new_with_range(1, MAX_PW - 1, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(w->gen_length), 16);
    gtk_box_pack_start(GTK_BOX(lenrow), w->gen_length, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), lenrow, FALSE, FALSE, 0);

    GtkWidget *clslbl = gtk_label_new("CHARACTER CLASSES");
    gtk_widget_set_halign(clslbl, GTK_ALIGN_START);
    add_class(clslbl, "section-label");
    gtk_box_pack_start(GTK_BOX(box), clslbl, FALSE, FALSE, 0);

    /* Two-column grid of class toggles. */
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 18);
    w->gen_lower  = gtk_check_button_new_with_label("Lowercase  a\xE2\x80\x93z");
    w->gen_upper  = gtk_check_button_new_with_label("Uppercase  A\xE2\x80\x93Z");
    w->gen_digit  = gtk_check_button_new_with_label("Numbers  0\xE2\x80\x93" "9");
    w->gen_symbol = gtk_check_button_new_with_label("Symbols  !@#$\xE2\x80\xA6");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w->gen_lower), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w->gen_upper), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w->gen_digit), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w->gen_symbol), TRUE);
    gtk_grid_attach(GTK_GRID(grid), w->gen_lower, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), w->gen_upper, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), w->gen_digit, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), w->gen_symbol, 1, 1, 1, 1);
    gtk_box_pack_start(GTK_BOX(box), grid, FALSE, FALSE, 0);

    GtkWidget *gen_btn = gtk_button_new_with_label("Generate Secure Password");
    add_class(gen_btn, "accent");
    g_signal_connect(gen_btn, "clicked",
                     G_CALLBACK(on_generate_clicked), w);
    gtk_box_pack_start(GTK_BOX(box), gen_btn, FALSE, FALSE, 0);

    GtkWidget *outrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    w->gen_output = gtk_entry_new();
    gtk_editable_set_editable(GTK_EDITABLE(w->gen_output), FALSE);
    add_class(w->gen_output, "password-display");
    gtk_entry_set_placeholder_text(GTK_ENTRY(w->gen_output),
                                   "Your password will appear here");
    gtk_box_pack_start(GTK_BOX(outrow), w->gen_output, TRUE, TRUE, 0);
    GtkWidget *copy_btn = gtk_button_new_with_label("Copy");
    g_signal_connect(copy_btn, "clicked", G_CALLBACK(on_copy_clicked), w);
    gtk_box_pack_start(GTK_BOX(outrow), copy_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), outrow, FALSE, FALSE, 0);

    GtkWidget *meter = make_strength_meter(&w->gen_bar, &w->gen_verdict);
    gtk_box_pack_start(GTK_BOX(box), meter, FALSE, FALSE, 0);

    GtkWidget *scroll = make_result_view();
    w->gen_result = g_object_get_data(G_OBJECT(scroll), "view");
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);

    return box;
}

/* Install the app's CSS theme on the default screen (once). */
static void load_css(void) {
    GtkCssProvider *provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(provider, APP_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

static void activate(GtkApplication *app, gpointer user_data) {
    (void)user_data;
    load_css();
    AppWidgets *w = g_new0(AppWidgets, 1);

    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Entropy");
    gtk_window_set_default_size(GTK_WINDOW(window), 520, 480);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);

    /* Header bar with an About button. */
    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "Entropy");
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
    GtkWidget *about_btn = gtk_button_new_with_label("About");
    g_signal_connect(about_btn, "clicked", G_CALLBACK(on_about_clicked), NULL);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), about_btn);
    gtk_window_set_titlebar(GTK_WINDOW(window), header);

    /* Window/taskbar icon: try the installed icon, fall back to theme name. */
    GError *err = NULL;
    if (!gtk_window_set_icon_from_file(GTK_WINDOW(window), ICON_PATH, &err)) {
        g_clear_error(&err);
        gtk_window_set_icon_name(GTK_WINDOW(window), "entropy");
    }

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    /* Hero strip: logo + title + tagline. */
    GtkWidget *hero = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 14);
    add_class(hero, "hero");
    GdkPixbuf *logo = gdk_pixbuf_new_from_file_at_size(ICON_PATH, 44, 44, NULL);
    if (logo) {
        GtkWidget *img = gtk_image_new_from_pixbuf(logo);
        g_object_unref(logo);
        gtk_box_pack_start(GTK_BOX(hero), img, FALSE, FALSE, 0);
    }
    GtkWidget *titles = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_valign(titles, GTK_ALIGN_CENTER);
    GtkWidget *t1 = gtk_label_new("Entropy");
    gtk_widget_set_halign(t1, GTK_ALIGN_START);
    add_class(t1, "hero-title");
    GtkWidget *t2 = gtk_label_new("ENTROPY ANALYSIS \xC2\xB7 SECURE GENERATION");
    gtk_widget_set_halign(t2, GTK_ALIGN_START);
    add_class(t2, "hero-subtitle");
    gtk_box_pack_start(GTK_BOX(titles), t1, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(titles), t2, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hero), titles, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), hero, FALSE, FALSE, 0);

    GtkWidget *notebook = gtk_notebook_new();
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
                             build_verify_tab(w),
                             gtk_label_new("Verify"));
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
                             build_generate_tab(w),
                             gtk_label_new("Generate"));
    gtk_box_pack_start(GTK_BOX(root), notebook, TRUE, TRUE, 0);

    gtk_container_add(GTK_CONTAINER(window), root);

    /* Free the widget bag when the window goes away. */
    g_object_set_data_full(G_OBJECT(window), "appwidgets", w, g_free);

    gtk_widget_show_all(window);
}

int main(int argc, char **argv) {
    /* Make the taskbar/.desktop association resolve to our icon name. */
    g_set_prgname("entropy");

    GtkApplication *app = gtk_application_new("org.toolkit.entropy",
                                              ENTROPY_APP_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}
