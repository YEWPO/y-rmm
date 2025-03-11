#ifndef PLANE_H
#define PLANE_H

#include <stdbool.h>

#define MAX_AUX_PLANES        3U

#define PLANE_TO_ARRAY(plane) ((plane) - 1)
#define ARRAY_TO_PLANE(array) ((array) + 1)

bool is_aux_plane(void);

#endif
