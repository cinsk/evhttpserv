#ifndef PATABLE_H__
#define PATABLE_H__

#define USE_PCRE

struct pentry;

struct patable {
  size_t npat;
  int cur;
  struct pentry *pat;
};

typedef void (*pat_callback)(int grpc, char *grpv[]);

int patable_init(struct patable *pat);
#if 0
int patable_exec(struct patable *table, const char *source, size_t len,
                 struct xobs *pool);
#endif

/* add a pattern to TABLE. returns nonzero on success */
int patable_add(struct patable *table, const char *pattern, const void *data);

/* release pattern table, PAT */
void patable_release(struct patable *pat);


#ifdef USE_PCRE
/* perform regular expression match on all patterns in TABLE against
 * SOURCE.  LEN is the length of the SOURCE unless it is (size_t)-1.
 * You should pass the OVECTOR which has OVSIZE numbers of int, to
 * calculate the subgroup.  It is advised for OVSIZE to be a multiple
 * of three.
 *
 * If there is a match, patable_match() returns the index of the
 * pattern entry (>= 0), and NGROUP is set to the number of subgroup
 * plus 1. */
int patable_match(struct patable *table, const char *source, size_t len,
                  int *ngroup, int *ovector, size_t ovsize);
/*
 * Build subgroup vector from OVECTOR and NGROUP from the previous
 * match.
 */
char **patable_groups(struct xobs *pool, size_t ngroup,
                      const char *source, const int *ovector);

/*
 * Convenient function to match the regular expression RE with EXTRA
 * in SOURCE with the length, LEN.  If LEN is (size_t)-1, it will be
 * calculated via strlen().   OVECTOR is used for captured subgroups.
 * and OVSIZE is the number of vectors in OVECTOR.    OVECTOR should be
 * larger than (1 + # of subgroups) * 3.  See pcreapi(3) for details.
 */
static __inline__ int
re_match(pcre *re, pcre_extra *extra, const char *source, size_t len,
         int *ovector, size_t ovsize)
{
  if (len == (size_t)-1)
    len = strlen(source);

  return pcre_exec(re, extra,
                   source, len,
                   0, /* start offset */
                   0, /* options */
                   ovector, ovsize);
}


/*
 * Convenient function to retrive the subgroups from the OVECTOR set
 * by re_match().  NGROUP is the number of subgroups + 1, which is the
 * return value of re_match().  re_groups() will returns an array of
 * pointers to subgroups.  The array and strings of subgroups are
 * allocated from POOL.  You'll need to pass the same source text,
 * SOURCE used in re_match().  To free all resources in re_groups(),
 * call xobs_free() on the returned pointer.  Note that re_groups()
 * will return NULL on errors, so make sure you call xobs_free() iff
 * when re_groups() succeeded.
 */
char **re_groups(struct xobs *pool, size_t ngroup,
                 const char *source, const int *ovector)
  __attribute__ ((alias("patable_groups")));


#else  /* USE_PCRE */
int patable_match(struct patable *table, const char *source, size_t len,
                  int *ngroup, regmatch_t *ovector, size_t ovsize);
char **patable_groups(struct xobs *pool, size_t ngroup,
                      const char *source, const regmatch_t *ovector);
#endif  /* USE_PCRE */

/*
 * Retrive the user data pointed by INDEX.
 */
void *patable_data(struct patable *table, int index);


/*
 * Release the subgroup vector built from patable_groups()
 */
void patable_free_groups(struct xobs *pool, char **grpv);

#endif /* PATABLE_H__ */
