#include "include/weir_objsec.h"

//INIT
int init_list(struct tag_list** list_pointer_address){
	*list_pointer_address = (struct tag_list*)kmalloc(sizeof(struct tag_list), GFP_KERNEL);
	if (!(*list_pointer_address)){
		return ENOMEM;
	}
	INIT_LIST_HEAD(&((*list_pointer_address)->list));
	return 0;
}
//INIT
int init_list2(struct tag_list* list_pointer_address){
	INIT_LIST_HEAD(&(list_pointer_address->list));
	return 0;
}

//COPY_INIT: Inits the destination and copies
void copy_init_list(struct tag_list* orig_list, struct tag_list** dest_list){
	init_list(dest_list);
	copy_list(orig_list, *dest_list);
}

//COPY
int copy_list(struct tag_list* orig_list, struct tag_list* new_list){
	struct list_head* pos;
	struct tag_list* tmp;
	if(orig_list==NULL || new_list==NULL){
	    return -1;
	}

	//printk("WEIR:copy_list both lists are not null. Size of orig = %d\n", list_size(orig_list));
	//Iterate to check if "value" exists in the list
	list_for_each(pos, &(orig_list->list)){
		tmp=list_entry(pos, struct tag_list, list);
		//printk("WEIR:copy_list adding %lld.\n", tmp->t);
		if(!exists_list(new_list, tmp->t)){
		    add_list(new_list, tmp->t);
		    //list_add(&(tmp->list), &(new_list->list));
		}
	}
	return 0;
}

//ADD
int add_list(struct tag_list* orig_list, tag_t value){
	struct tag_list *to_add;
	if(orig_list==NULL){
	    //printk("WEIR:add_list NULL for value %lld, returning.\n",value);
	    return -1;
	}
	//printk("WEIR:add_list not NULL for value %lld, returning.\n",value);
	if(exists_list(orig_list, value)){
	    return -1;
	}
	//Initialize the new node, assign it "value"
	to_add = (struct tag_list*)kmalloc(sizeof(struct tag_list), GFP_KERNEL);
	if (to_add==NULL){
		return ENOMEM;
	}
	to_add->t = value;
	//Add it to the list
	list_add(&(to_add->list), &(orig_list->list));

	return 0;
}

//EXISTS
bool exists_list(struct tag_list* orig_list, tag_t value){
	struct list_head* pos;
	struct tag_list* tmp;

	if(orig_list==NULL){
		return false;
	}
	
	//Iterate to check if "value" exists in the list
	list_for_each(pos, &(orig_list->list)){
		tmp=list_entry(pos, struct tag_list, list);
		//Return true if found
		if(tmp->t == value){
			return true;
		}
	}

	return false;
}

//REMOVE
int remove_list(struct tag_list* orig_list, tag_t value){
	struct list_head *pos, *q;
	struct tag_list* tmp;

	if(orig_list==NULL){
		return -1;
	}
	
	//Iterate to check if "value" exists in the list
	list_for_each_safe(pos, q, &(orig_list->list)){
		tmp=list_entry(pos, struct tag_list, list);
		//Remove if found
		if(tmp->t == value){
			list_del(pos);
			kfree(tmp);
			return 0;
		}
	}

	return 0;
}

//SIZE
int list_size(struct tag_list* orig_list){
	struct list_head* pos;
	int size=0;
	if(orig_list==NULL){
		return -1;
	}
	
	//printk("WEIR:list_size orig_list not NULL.\n");
	//Iterate to check if "value" exists in the list
	list_for_each(pos, &(orig_list->list)){
	    //printk("WEIR:list_size in list_for_each, size_counter=%d.\n", size);
	    size++;
	}

	return size;
}

//PRINT
int list_print(struct tag_list* orig_list){
	struct list_head* pos;
	struct tag_list* tmp;
	if(orig_list==NULL){
		printk("{}\n");
		return -1;
	}
	
	printk("{");
	//Iterate
	list_for_each(pos, &(orig_list->list)){
	    tmp=list_entry(pos, struct tag_list, list);
	    printk("%lld, ",tmp->t);
	}
	printk("}\n");

	return 0;
}

//EMPTY
bool is_empty(struct tag_list* orig_list){
	if(list_size(orig_list)==0){
		return true;
	}
	return false;
}

// DOMINATES (i.e., a>=b)
bool dominates(struct tag_list* A, struct tag_list* B){
    struct list_head* pos;
	struct tag_list* tmp;

	//Everything dominates the lowest label.
	if(B==NULL || is_empty(B)){
		return true;
	}

	//If A is empty or NULL, it can dominate iff B is empty or null
	if(A==NULL || is_empty(A)){
		if(B==NULL || is_empty(B)){
			return true;
		} else {
			return false;
		}
	}

	list_for_each(pos, &(B->list)){
		tmp=list_entry(pos, struct tag_list, list);
		//If A does not contain the item in tmp, A does not dominate
		if(!exists_list(A, tmp->t)){
			return false;
		}
	}
	
	//A clearly dominates B at this point.
	return true;	
}

// DOMINATES (i.e., a>=b)
bool equals(struct tag_list* A, struct tag_list* B){
    if(dominates(A,B) && dominates(B,A)) {
	return true;
    }
    return false;
}

//UNION
void union_list(struct tag_list* A, struct tag_list* B, struct tag_list** C) {
	//If both the sets empty, so is the union
	if((A==NULL || is_empty(A)) && (B==NULL || is_empty(B))){
		*C = NULL;
		return;
	}

	//If only A is empty, make a copy of B and return.
	if(A==NULL || is_empty(A)){
		copy_init_list(B, C);
		return;
	} 

	//If only B is empty, make a copy of A and return.
	if(B==NULL || is_empty(B)){
		copy_init_list(A, C);
		return;
	}

	//Since both are not null, then we copy both one by one, but init only once.
	copy_init_list(A, C);
	copy_list(B, *C);
	return;
}
