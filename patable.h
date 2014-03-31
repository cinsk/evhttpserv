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
