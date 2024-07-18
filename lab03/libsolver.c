#include "got.c"
#include "got_.c"
#include "libmaze.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

const char *_fn = "/maze.txt";

maze_t *_maze_load(const char *fn);

int _solve(maze_t *mz, int *dir) {
  if (mz->blk[mz->cy][mz->cx]) {
    return 0;
  }
  mz->blk[mz->cy][mz->cx] = 1;

  static int _dirx[] = {0, 0, -1, 1};
  static int _diry[] = {-1, 1, 0, 0};

  for (int i = 0; i < 4; i++) {
    int nx = mz->cx + _dirx[i];
    int ny = mz->cy + _diry[i];
    if (nx >= 0 && nx < mz->w && ny >= 0 && ny < mz->h) {
      if (mz->blk[ny][nx] == 0) {
        dir[0] = i;

        if (nx == mz->ex && ny == mz->ey) {
          return 1;
        }

        mz->cx = nx;
        mz->cy = ny;
        int ret = _solve(mz, dir + 1);
        mz->cx -= _dirx[i];
        mz->cy -= _diry[i];

        if (ret) {
          return ret + 1;
        }
      }
    }
  }

  mz->blk[mz->cy][mz->cx] = 0;

  return 0;
}

int maze_init() {
  printf("UP112_GOT_MAZE_CHALLENGE\n");

  void *main_ptr = maze_get_ptr();
  printf("SOLVER: _main = %p\n", main_ptr);

  void *base_ptr = main_ptr - 0x1b7a9;

  long *move_1_got_ptr = (long *)(base_ptr + got_offset[0]);

  long move_ptr[4];
  move_ptr[0] = *move_1_got_ptr - 0xc7be + 0xc6fb;
  move_ptr[1] = *move_1_got_ptr - 0xc7be + 0xc71f;
  move_ptr[2] = *move_1_got_ptr - 0xc7be + 0xc743;
  move_ptr[3] = *move_1_got_ptr - 0xc7be + 0xc767;

  maze_t *mz = _maze_load(_fn);
  int dir[1200];
  int length = _solve(mz, dir);

  printf("Length: %d\n", length);
  for (int i = 0; i < length; i++) {
    printf("%d ", dir[i]);

    long *move_got_ptr = (long *)(base_ptr + got_offset[i]);
    mprotect((void *)(((long)move_got_ptr) & ~0xfff), 0x1000,
             PROT_READ | PROT_WRITE);
    *move_got_ptr = move_ptr[dir[i]];
  }

  return 0;
}

maze_t *_maze_load(const char *fn) {
  maze_t *mz = NULL;
  FILE *fp = NULL;
  int i, j, k;
  //
  if ((fp = fopen(fn, "rt")) == NULL) {
    // fprintf(stderr, "MAZE: fopen failed - %s.\n", strerror(errno));
    return NULL;
  }
  if ((mz = (maze_t *)malloc(sizeof(maze_t))) == NULL) {
    // fprintf(stderr, "MAZE: alloc failed - %s.\n", strerror(errno));
    goto err_quit;
  }
  if (fscanf(fp, "%d %d %d %d %d %d", &mz->w, &mz->h, &mz->sx, &mz->sy, &mz->ex,
             &mz->ey) != 6) {
    // fprintf(stderr, "MAZE: load dimensions failed - %s.\n", strerror(errno));
    goto err_quit;
  }
  mz->cx = mz->sx;
  mz->cy = mz->sy;
  for (i = 0; i < mz->h; i++) {
    for (j = 0; j < mz->w; j++) {
      if (fscanf(fp, "%d", &k) != 1) {
        // fprintf(stderr, "MAZE: load blk (%d, %d) failed - %s.\n", j, i,
        //        strerror(errno));
        goto err_quit;
      }
      mz->blk[i][j] = k << 20;
    }
  }
  fclose(fp);
  // fprintf(stderr, "MAZE: loaded [%d, %d]: (%d, %d) -> (%d, %d)\n", mz->w,
  // mz->h,
  //        mz->sx, mz->sy, mz->ex, mz->ey);
  return mz;
err_quit:
  if (mz)
    free(mz);
  if (fp)
    fclose(fp);
  return NULL;
}
