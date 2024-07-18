/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/cdev.h>
#include <linux/cred.h> // for current_uid();
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/init.h>   // included for __init and __exit macros
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/module.h> // included for all kernel modules
#include <linux/proc_fs.h>
#include <linux/sched.h> // task_struct requried for current_uid()
#include <linux/seq_file.h>
#include <linux/slab.h> // for kmalloc/kfree
#include <linux/string.h>
#include <linux/uaccess.h> // copy_to_user

#include <maze.h>

#define _MAZE_WALL '#'
#define _MAZE_ROAD '.'

#define _MAZE_CUR "*"
#define _MAZE_END "E"

static DEFINE_MUTEX(maze_mutex);

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static uid_t maze_pids[_MAZE_MAXUSER];
static maze_t maze_mazes[_MAZE_MAXUSER];
static coord_t maze_curpos[_MAZE_MAXUSER];

static int maze_path_stack_count[_MAZE_MAXUSER];
static coord_t maze_path_stack[_MAZE_MAXUSER][_MAZE_MAXX * _MAZE_MAXY];

static const int maze_moves[4][2] = {
    {0, -1}, // up
    {1, 0},  // right
    {0, 1},  // down
    {-1, 0}  // left
};

static int maze_pid_to_uid(pid_t pid) {
  mutex_lock(&maze_mutex);
  for (int uid = 0; uid < _MAZE_MAXUSER; ++uid) {
    if (pid == maze_pids[uid]) {
      mutex_unlock(&maze_mutex);
      return uid;
    }
  }
  mutex_unlock(&maze_mutex);
  return -1;
}

static int maze_uid_occupied(int uid) {
  mutex_lock(&maze_mutex);
  bool ret = maze_pids[uid] != 0;
  mutex_unlock(&maze_mutex);
  return ret;
}

static void maze_uid_set(int uid, pid_t pid) {
  mutex_lock(&maze_mutex);
  maze_pids[uid] = pid;
  mutex_unlock(&maze_mutex);
}

static void maze_uid_free(int uid) {
  mutex_lock(&maze_mutex);
  maze_pids[uid] = 0;
  mutex_unlock(&maze_mutex);
}

static coord_t maze_choose_next_cell(coord_t *curpos, maze_t *maze,
                                     coord_t *path_stack,
                                     int *path_stack_count) {
  int i;
  int x, y;
  int next_cell_list_cnt = 0;
  coord_t next_cell_list[4];

  for (i = 0; i < 4; ++i) {
    x = curpos->x + (maze_moves[i][0] << 1);
    y = curpos->y + (maze_moves[i][1] << 1);
    if (x < 0 || x >= maze->w || y < 0 || y >= maze->h) {
      continue;
    }
    if (maze->blk[y][x] == _MAZE_ROAD) {
      continue;
    }
    next_cell_list[next_cell_list_cnt].x = x;
    next_cell_list[next_cell_list_cnt].y = y;
    ++next_cell_list_cnt;
  }
  if (next_cell_list_cnt == 0) {
    next_cell_list[0].x = -1;
    next_cell_list[0].y = -1;
    return next_cell_list[0];
  }
  return next_cell_list[get_random_u32() % next_cell_list_cnt];
}

static void maze_generate_one_step(coord_t *curpos, maze_t *maze,
                                   coord_t *path_stack, int *path_stack_count) {
  int x, y;
  coord_t ret;
  coord_t next_cell =
      maze_choose_next_cell(curpos, maze, path_stack, path_stack_count);

  if (next_cell.x == -1) {
    if (*path_stack_count == 0) {
      return;
    }
    ret = path_stack[--(*path_stack_count)];
    curpos->x = ret.x;
    curpos->y = ret.y;
    return;
  }

  path_stack[(*path_stack_count)++] = *curpos;

  x = (curpos->x + next_cell.x) >> 1;
  y = (curpos->y + next_cell.y) >> 1;

  maze->blk[y][x] = _MAZE_ROAD;
  maze->blk[next_cell.y][next_cell.x] = _MAZE_ROAD; // mark as visited

  curpos->x = next_cell.x;
  curpos->y = next_cell.y;
}

int depth[_MAZE_MAXY][_MAZE_MAXX];
int queue[_MAZE_MAXX * _MAZE_MAXY][2];

static void maze_decide_end(maze_t *maze) {
  int i, j;
  int x, y;
  int max_depth = 0;
  int max_depth_x, max_depth_y;
  int queue_head = 0;
  int queue_tail = 0;

  for (i = 0; i < maze->h; ++i) {
    for (j = 0; j < maze->w; ++j) {
      depth[i][j] = -1;
    }
  }

  depth[maze->sy][maze->sx] = 0;
  queue[queue_tail][0] = maze->sx;
  queue[queue_tail][1] = maze->sy;
  ++queue_tail;

  while (queue_head < queue_tail) {
    x = queue[queue_head][0];
    y = queue[queue_head][1];
    ++queue_head;

    for (i = 0; i < 4; ++i) {
      int nx = x + maze_moves[i][0];
      int ny = y + maze_moves[i][1];
      if (nx < 0 || nx >= maze->w || ny < 0 || ny >= maze->h) {
        continue;
      }
      if (maze->blk[ny][nx] == _MAZE_WALL) {
        continue;
      }
      if (depth[ny][nx] != -1) {
        continue;
      }
      depth[ny][nx] = depth[y][x] + 1;
      queue[queue_tail][0] = nx;
      queue[queue_tail][1] = ny;
      ++queue_tail;
    }
  }

  for (i = 0; i < maze->h; ++i) {
    for (j = 0; j < maze->w; ++j) {
      if (depth[i][j] > max_depth) {
        max_depth = depth[i][j];
        max_depth_x = j;
        max_depth_y = i;
      }
    }
  }

  maze->ex = max_depth_x;
  maze->ey = max_depth_y;
}

static long maze_create(coord_t *arg) {
  int i, j;
  int uid;

  if (arg->x < 0 || arg->y < 0) {
    return -EINVAL;
  }

  uid = maze_pid_to_uid(current->pid);

  if (uid != -1) {
    return -EEXIST;
  }

  for (uid = 0; uid < _MAZE_MAXUSER; ++uid) {
    if (!maze_uid_occupied(uid)) {
      maze_uid_set(uid, current->pid);
      break;
    }
  }

  if (uid == _MAZE_MAXUSER) {
    return -ENOMEM;
  }

  maze_mazes[uid].w = arg->x;
  maze_mazes[uid].h = arg->y;
  maze_mazes[uid].sx = (get_random_u32() % (arg->x >> 1) << 1) + 1;
  maze_mazes[uid].sy = (get_random_u32() % (arg->y >> 1) << 1) + 1;

  maze_curpos[uid].x = maze_mazes[uid].sx;
  maze_curpos[uid].y = maze_mazes[uid].sy;

  // Initialize the maze to all 0
  for (i = 0; i < arg->y; ++i) {
    for (j = 0; j < arg->x; ++j) {
      maze_mazes[uid].blk[i][j] =
          0; // It will be filled with road after maze generation
    }
  }

  // Set the even column and row to wall
  for (i = 0; i < arg->x; i += 2) {
    for (j = 0; j < arg->y; ++j) {
      maze_mazes[uid].blk[j][i] = _MAZE_WALL;
    }
  }
  for (i = 0; i < arg->y; i += 2) {
    for (j = 0; j < arg->x; ++j) {
      maze_mazes[uid].blk[i][j] = _MAZE_WALL;
    }
  }

  // Generate the maze
  maze_mazes[uid].blk[maze_mazes[uid].sy][maze_mazes[uid].sx] =
      _MAZE_ROAD; // mark as visited
  maze_path_stack[uid][0].x = maze_mazes[uid].sx;
  maze_path_stack[uid][0].y = maze_mazes[uid].sy;
  maze_path_stack_count[uid] = 1;

  while (maze_path_stack_count[uid] > 0) {
    maze_generate_one_step(&maze_curpos[uid], &maze_mazes[uid],
                           maze_path_stack[uid], &maze_path_stack_count[uid]);
  }

  maze_decide_end(&maze_mazes[uid]);

  return 0;
}

static long maze_reset(void) {
  int uid = maze_pid_to_uid(current->pid);
  if (uid == -1) {
    return -ENOENT;
  }
  maze_curpos[uid].x = maze_mazes[uid].sx;
  maze_curpos[uid].y = maze_mazes[uid].sy;
  return 0;
}

static long maze_destroy(void) {
  int uid = maze_pid_to_uid(current->pid);
  if (uid == -1) {
    return -ENOENT;
  }
  maze_uid_free(uid);
  return 0;
}

static long maze_getsize(coord_t *arg) {
  int uid = maze_pid_to_uid(current->pid);
  if (uid == -1) {
    return -ENOENT;
  }
  arg->x = maze_mazes[uid].w;
  arg->y = maze_mazes[uid].h;
  return 0;
}

static long maze_move(coord_t *arg) {
  int i;
  int x, y;
  int uid = maze_pid_to_uid(current->pid);

  if (uid == -1) {
    return -ENOENT;
  }

  for (i = 0; i < 4; ++i) {
    if (arg->x == maze_moves[i][0] && arg->y == maze_moves[i][1]) {
      break;
    }
  }
  if (i == 4) {
    return 0;
  }

  x = maze_curpos[uid].x + arg->x;
  y = maze_curpos[uid].y + arg->y;

  if (maze_mazes[uid].blk[y][x] == _MAZE_WALL) {
    return 0;
  }

  maze_curpos[uid].x = x;
  maze_curpos[uid].y = y;

  return 0;
}

static long maze_getpos(coord_t *arg) {
  int uid = maze_pid_to_uid(current->pid);
  if (uid == -1) {
    return -ENOENT;
  }
  arg->x = maze_curpos[uid].x;
  arg->y = maze_curpos[uid].y;
  return 0;
}

static long maze_getstart(coord_t *arg) {
  int uid = maze_pid_to_uid(current->pid);
  if (uid == -1) {
    return -ENOENT;
  }
  arg->x = maze_mazes[uid].sx;
  arg->y = maze_mazes[uid].sy;
  return 0;
}

static long maze_getend(coord_t *arg) {
  int uid = maze_pid_to_uid(current->pid);
  if (uid == -1) {
    return -ENOENT;
  }
  arg->x = maze_mazes[uid].ex;
  arg->y = maze_mazes[uid].ey;
  return 0;
}

static int maze_dev_open(struct inode *i, struct file *f) { return 0; }

static int maze_dev_close(struct inode *i, struct file *f) {
  maze_uid_free(maze_pid_to_uid(current->pid));
  return 0;
}

static ssize_t maze_dev_read(struct file *f, char __user *buf, size_t len,
                             loff_t *off) {
  int i, j;
  int uid;
  size_t size;
  static char maze_one = 1;
  static char maze_zero = 0;

  uid = maze_pid_to_uid(current->pid);
  if (uid == -1) {
    return -EBADFD;
  }

  size = maze_mazes[uid].w * maze_mazes[uid].h;

  for (i = 0; i < maze_mazes[uid].h; ++i) {
    for (j = 0; j < maze_mazes[uid].w; ++j) {
      if (maze_mazes[uid].blk[i][j] == _MAZE_WALL) {
        if (copy_to_user(buf, &maze_one, sizeof(char))) {
          return -EBUSY;
        }
      } else {
        if (copy_to_user(buf, &maze_zero, sizeof(char))) {
          return -EBUSY;
        }
      }
      ++buf;
    }
  }

  return size;
}

static ssize_t maze_dev_write(struct file *f, const char __user *buf,
                              size_t len, loff_t *off) {
  int i;
  int uid;
  long ret;
  coord_t *moves;

  uid = maze_pid_to_uid(current->pid);
  if (uid == -1) {
    return -EBADFD;
  }

  moves = kmalloc(len, GFP_KERNEL);
  if (copy_from_user(moves, buf, len)) {
    // kfree(moves);
    return -EBUSY;
  }

  if (len % sizeof(coord_t) != 0) {
    // kfree(moves);
    return -EINVAL;
  }

  for (i = 0; i < len / sizeof(coord_t); ++i) {
    ret = maze_move(&moves[i]);
    if (ret) {
      // kfree(moves);
      return ret;
    }
  }

  // kfree(moves);
  return len;
}

static long maze_dev_ioctl(struct file *fp, unsigned int cmd,
                           unsigned long arg) {
  switch (cmd) {
  case MAZE_CREATE:
    return maze_create((coord_t *)arg);
  case MAZE_RESET:
    return maze_reset();
  case MAZE_DESTROY:
    return maze_destroy();
  case MAZE_GETSIZE:
    return maze_getsize((coord_t *)arg);
  case MAZE_MOVE:
    return maze_move((coord_t *)arg);
  case MAZE_GETPOS:
    return maze_getpos((coord_t *)arg);
  case MAZE_GETSTART:
    return maze_getstart((coord_t *)arg);
  case MAZE_GETEND:
    return maze_getend((coord_t *)arg);
  default:
    return -EINVAL;
  }
  return 0;
}

static const struct file_operations maze_dev_fops = {.owner = THIS_MODULE,
                                                     .open = maze_dev_open,
                                                     .read = maze_dev_read,
                                                     .write = maze_dev_write,
                                                     .unlocked_ioctl =
                                                         maze_dev_ioctl,
                                                     .release = maze_dev_close};

static int maze_proc_read(struct seq_file *m, void *v) {
  int i, j, k;

  for (i = 0; i < _MAZE_MAXUSER; ++i) {
    if (!maze_uid_occupied(i)) {
      seq_printf(m, "#%02d: vacancy\n\n", i);
    } else {
      mutex_lock(&maze_mutex);
      seq_printf(m,
                 "#%02d: pid %d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d, %d)\n",
                 i, maze_pids[i], maze_mazes[i].w, maze_mazes[i].h,
                 maze_mazes[i].sx, maze_mazes[i].sy, maze_mazes[i].ex,
                 maze_mazes[i].ey, maze_curpos[i].x, maze_curpos[i].y);
      mutex_unlock(&maze_mutex);
      for (j = 0; j < maze_mazes[i].h; ++j) {
        seq_printf(m, "- %03d: ", j);
        for (k = 0; k < maze_mazes[i].w; ++k) {
          if (k == maze_curpos[i].x && j == maze_curpos[i].y) {
            seq_printf(m, _MAZE_CUR);
          } else if (k == maze_mazes[i].ex && j == maze_mazes[i].ey) {
            seq_printf(m, _MAZE_END);
          } else {
            seq_printf(m, "%c", maze_mazes[i].blk[j][k]);
          }
        }
        seq_printf(m, "\n");
      }
      seq_printf(m, "\n");
    }
  }

  return 0;
}

static int maze_proc_open(struct inode *inode, struct file *file) {
  return single_open(file, maze_proc_read, NULL);
}

static const struct proc_ops maze_proc_fops = {
    .proc_open = maze_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static char *maze_devnode(const struct device *dev, umode_t *mode) {
  if (mode == NULL)
    return NULL;
  *mode = 0666;
  return NULL;
}

static int __init maze_init(void) {
  if (alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
    return -1;
  if ((clazz = class_create("upclass")) == NULL)
    goto release_region;
  clazz->devnode = maze_devnode;
  if (device_create(clazz, NULL, devnum, NULL, "maze") == NULL)
    goto release_class;
  cdev_init(&c_dev, &maze_dev_fops);
  if (cdev_add(&c_dev, devnum, 1) == -1)
    goto release_device;

  proc_create("maze", 0, NULL, &maze_proc_fops);

  return 0; // Non-zero return means that the module couldn't be loaded.

release_device:
  device_destroy(clazz, devnum);
release_class:
  class_destroy(clazz);
release_region:
  unregister_chrdev_region(devnum, 1);
  return -1;
}

static void __exit maze_cleanup(void) {
  remove_proc_entry("maze", NULL);

  cdev_del(&c_dev);
  device_destroy(clazz, devnum);
  class_destroy(clazz);
  unregister_chrdev_region(devnum, 1);
}

module_init(maze_init);
module_exit(maze_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jun-Hong Cheng");
MODULE_DESCRIPTION(
    "The unix programming course lab2 kernel module providing a maze.");
