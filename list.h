#ifndef LIST_H_
#define LIST_H_

typedef struct list_head {
  struct list_head *next;
  struct list_head *prev;
} list_head_t;

#define LIST_GET_ENTRY(list_member, structure_type, list_field) \
        ((structure_type*)((char*)(list_member) - \
                          ((char*)&((structure_type*)0)->list_field - (char*)0)))

static inline void list_init(list_head_t *lst) {
  lst->next = lst;
  lst->prev = lst;
}

static inline void list_add(list_head_t *lst, list_head_t *new_item) {
  new_item->next = lst->next;
  new_item->prev = lst;
  lst->next->prev = new_item;
  lst->next = new_item;
}

static inline void list_del(list_head_t *item) {
  item->next->prev = item->prev;
  item->prev->next = item->next;
}

static inline void list_replace(list_head_t *old_el, list_head_t *new_el) {
  new_el->next = old_el->next;
  new_el->prev = old_el->prev;
  old_el->next->prev = new_el;
  old_el->prev->next = new_el;
}

static inline int list_is_empty(list_head_t *item) {
  return item == item->next;
}

static inline void list_move_elements(list_head_t *src, list_head_t *dst) {
  if (list_is_empty(src)) {
    list_init(dst);
    return;
  }
  list_head_t *n = src->next;
  list_head_t *p = src->prev;
  dst->next = n;
  n->prev = dst;
  dst->prev = p;
  p->next = dst;
  list_init(src);
}

/**
 * \brief Посчитать количество элементов в списке (голову не считает за элемент списка).
 * \return Возвращает количество элементов в списке.
 */
static inline int list_size(list_head_t *lst) {
  int size = 0;
  list_head_t *cur = lst->next;
  while (cur != lst) {
    size ++;
    cur = cur->next;
  }
  return size;
}

#endif /* LIST_H_ */

