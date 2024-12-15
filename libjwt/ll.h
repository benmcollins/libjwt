#ifndef LL_H__
#define LL_H__

/* 
 * Copyright 2022 Embedded Artistry LLC
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdint.h>
#include <stdlib.h> //size_t, NULL

/** @defgroup linkedlist-C C Linked List Interface
 * A linked list library for C modules
 *
 * @ingroup FrameworkUtils
 * @{
 */

/**
 * Define offsetof if we don't have it already
 */
#ifndef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE*)0)->MEMBER)
#endif
#endif // offsetof

/**
 * Define container_of if we don't have it already
 */
#ifndef container_of
#ifdef __GNUC__
#ifndef __clang__
// Isolate the GNU-specific expression
#define container_of(ptr, type, member)                       \
	({                                                        \
		const __typeof__(((type*)0)->member)* __mptr = (ptr); \
		(type*)((uintptr_t)__mptr - offsetof(type, member));  \
	})
#else // we are clang - avoid GNU expression
#define container_of(ptr, type, member) ((type*)((uintptr_t)(ptr)-offsetof(type, member)))
#endif // GNU and not clang
#else
#define container_of(ptr, type, member) ((type*)((uintptr_t)(ptr)-offsetof(type, member)))
#endif // not GNU
#endif // container_of

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/** Linked list struct
 *
 * This is a doubly linked list structure.
 * The ll_t structure should be embedded in a container structure that you want to list.
 *
 * Example:
 *
 * @code
 * typedef struct
 * {
 * 	ll_t node;
 * 	size_t size;
 * 	char* block;
 * } alloc_node_t;
 * @endcode
 */
typedef struct ll_head
{
	/// Pointer to the next element in the list.
	struct ll_head* next;
	/// Pointer to the previous element in the list.
	struct ll_head* prev;
} ll_t;

/// @name Get Containers
/// @{

/** Get the container for a list entry
 *
 * @param[in] ptr The pointer to the target ll_t node.
 * @param[in] type The struct type which contains the ll_t node. For this example struct,
 * type would refer to alloc_node_t:
 * @code
 * typedef struct
 * {
 * 	ll_t node;
 * 	size_t size;
 * 	char* block;
 * } alloc_node_t;
 * @endcode
 *
 * @param[in] member The member which corresponds to the member name of the ll_t entry. For this
 * example struct, member would refer to `node`.
 * @code
 * typedef struct
 * {
 * 	ll_t node;
 * 	size_t size;
 * 	char* block;
 * } alloc_node_t;
 * @endcode
 *
 * @returns a pointer to the struct containing the linked list node at `ptr`, cast to type `type`.
 */
#define list_entry(ptr, type, member) container_of(ptr, type, member)

/** Get the container for the first item in the list
 *
 * @param[in] head The pointer to the head of the list.
 * @param[in] type The struct type which contains the ll_t node. For this example struct,
 * type would refer to alloc_node_t:
 * @code
 * typedef struct
 * {
 * 	ll_t node;
 * 	size_t size;
 * 	char* block;
 * } alloc_node_t;
 * @endcode

 * @param[in] member The member which corresponds to the member name of the ll_t entry. For this
 * example struct, member would refer to `node`.
 * @code
 * typedef struct
 * {
 * 	ll_t node;
 * 	size_t size;
 * 	char* block;
 * } alloc_node_t;
 * @endcode
 *
 * @returns a pointer to the struct containing the linked list node at `ptr`, cast to type `type`.
 */
#define list_first_entry(head, type, member) list_entry((head)->next, type, member)

/// @}
// Get containers

/// @name Foreach Operations
/// @{

/** Declare a foreach loop which iterates over the list
 *
 * list_for_each() will run as long as the current object's next pointer is not equal to the
 * head of the list. It's possible for a malformed list to loop forever.
 *
 * @param[in] pos The variable which will hold the current iteration's position value.
 *	This variable must be a pointer and should be pre-declared before instantiating the loop.
 *	@code
 *	ll_t *b;
 *	list_for_each(b, &free_list)
 *   {
 *	...
 * 	}
 *   @endcode
 * @param[in] head The head of the linked list. Input should be a pointer.
 */
#define list_for_each(pos, head) for(pos = (head)->next; pos != (head); pos = pos->next)

/** Declare a foreach loop which iterates over the list, copy current node pointer.
 *
 * list_for_each_safe() will run as long as the current object's next pointer is not equal to the
 * head of the list. It's possible for a malformed list to loop forever.
 *
 * The list_for_each_safe() variant makes a copy of the current node pointer, enabling the loop
 * to get to the next pointer if there is a deletion.
 *
 * @param[in] pos The variable which will hold the current iteration's position value.
 *	This variable must be a pointer should be pre-declared before instantiating the loop.
 *	@code
 *	ll_t *b, *t;
 *	list_for_each_safe(b, t, &free_list)
 *   {
 *	...
 * 	}
 *  @endcode
 * @param[in] n The variable which will hold the current iteration's position value **copy**.
 *	This variable must be a pointer and should be pre-declared before instantiating the loop.
 *	@code
 *	alloc_node_t *b, *t;
 *	list_for_each_safe(b, t, &free_list)
 *   {
 *	...
 * 	}
 *	@endcode
 * @param[in] head The head of the linked list. Input should be a pointer.
 */
#define list_for_each_safe(pos, n, head) \
	for(pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)

/** Declare a for loop which operates on each node in the list using the container value.
 *
 * @param[in] pos The variable which will hold the current iteration's position value.
 *	This variable must be a pointer and should be pre-declared before instantiating the loop.
 *  The `pos` variable must be the container type.
 *	@code
 *	alloc_node_t *b, *t;
 *	list_for_each_entry(b, &free_list, node)
 *   {
 *	...
 * 	}
 *  @endcode
 *
 * @param[in] head The head of the linked list. Input should be a pointer.
 *
 * @param[in] member The member which corresponds to the member name of the ll_t entry. For this
 * example struct, member would refer to `node`.
 * @code
 * typedef struct
 * {
 * 	ll_t node;
 * 	size_t size;
 * 	char* block;
 * } alloc_node_t;
 * @endcode
 */
#define list_for_each_entry(pos, head, member)                                            \
	for(pos = list_entry((head)->next, __typeof__(*pos), member); &pos->member != (head); \
		pos = list_entry(pos->member.next, __typeof__(*pos), member))

/** Declare a for loop which operates on each node in the list using a copy of the container value.
 *
 * @param[in] pos The variable which will hold the current iteration's position value.
 *	This variable must be a pointer and should be pre-declared before instantiating the loop.
 *  The `pos` variable must be the container type.
 *	@code
 *	alloc_node_t *b, *t;
 *	list_for_each_entry(b, &free_list, node)
 *   {
 *	...
 * 	}
 *  @endcode
 * @param[in] n The variable which will hold the current iteration's position value **copy**.
 *	This variable must be a pointer and should be pre-declared before instantiating the loop.
 *  The `n` variable must be the container type.
 *	@code
 * typedef struct
 * {
 * 	ll_t node;
 * 	size_t size;
 * 	char* block;
 * } alloc_node_t;
 *
 *	alloc_node_t *b, *t;
 *	list_for_each_entrysafe(b, t, &free_list, node)
 *   {
 *	...
 * 	}
 *   @endcode
 * @param[in] head The head of the linked list. Input should be a pointer.
 * @param[in] member The member which corresponds to the member name of the ll_t entry. For this
 * example struct, member would refer to `node`.
 * @code
 * typedef struct
 * {
 * 	ll_t node;
 * 	size_t size;
 * 	char* block;
 * } alloc_node_t;
 * @endcode
 */
#define list_for_each_entry_safe(pos, n, head, member)            \
	for(pos = list_entry((head)->next, __typeof__(*pos), member), \
	n = list_entry(pos->member.next, __typeof__(*pos), member);   \
		&pos->member != (head); pos = n, n = list_entry(n->member.next, __typeof__(*n), member))

/// @}
// End foreach

/// @name Initialization
/// @{

/// Initialize a linked list so it points to itself
/// @param[in] name of the linked list object
#define ll_head_INIT(name) \
	{                      \
		&(name), &(name)   \
	}

// Added by BenC
static inline void INIT_LIST_HEAD(ll_t *list)
{
        list->next = list;
        list->prev = list;
}

/** Initialize a linked list
 *
 * @code
 * // This macro declares and initializes our linked list
 * static LIST_INIT(free_list);
 * @endcode
 * @param[in] name The name of the linked list object to declare
 */
#define LIST_INIT(name) struct ll_head name = ll_head_INIT(name)

/// @}

/// @name Addition
/// @{

/// Insert a new element between two existing elements.
/// @param[in] n The node to add to the list.
/// @param[in] prev The pointer to the node before where the new node will be inserted.
/// @param[in] next The pointer to the new node after where the new node will be inserted.
static inline void list_insert(struct ll_head* n, struct ll_head* prev, struct ll_head* next)
{
	next->prev = n;
	n->next = next;
	n->prev = prev;
	prev->next = n;
}

/// Add a node to the front of the list
/// @param[in] n The node to add to the list.
/// @param[in] head The head of the list.
static inline void list_add(struct ll_head* n, struct ll_head* head)
{
	list_insert(n, head, head->next);
}

/// Add a node to the end of the list
/// @param[in] n The node to add to the list.
/// @param[in] head The head of the list.
static inline void list_add_tail(struct ll_head* n, struct ll_head* head)
{
	list_insert(n, head->prev, head);
}

/// @}

/// @name Deletion
/// @{

/// Remove the node between two element pointers.
///
/// Joins the `prev` and `next` elements together, effectively removing
/// the element in the middle.
///
/// @param[in] prev The previous element in the list, which will now be joined to next.
/// @param[in] next The next element in the list, which will now be joined to prev.
static inline void list_join_nodes(struct ll_head* prev, struct ll_head* next)
{
	next->prev = prev;
	prev->next = next;
}

/// Remove an entry from the list
/// @param[in] entry The pointer to the entry to remove from the list.
static inline void list_del(struct ll_head* entry)
{
	list_join_nodes(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}

/// @}

/// @}
// end group

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // LL_H__
