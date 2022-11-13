/*
 * this file includes dictionary tree data struture
 * written by Qu Peiran on 2020.6.1
 */

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
struct node;
typedef struct
{
    struct node *p_node;
}tree;
typedef struct node 
{
    char letter;	// place letter in the string
    int offset;	// place the location of string originating from root node
    tree sibling;	// point to sibling node
    tree son;	// point to child
}node;

// initialize tree
void initTree(tree *p_tree){
	p_tree->p_node = NULL;
}

// release memory recursively
void destroyTree(tree *p_tree){
	if(p_tree->p_node==NULL) return;
	destroyTree(&(p_tree->p_node->sibling));
	destroyTree(&(p_tree->p_node->son));
	free(p_tree->p_node);
	p_tree->p_node=NULL;
}

/* 
 * insert new string to tree
 * if tree contains this string, return its location
 * if the string is new, insert it to tree, record its location and return 0
 */
int insertWord(tree *p_tree, char *word, int offset){
	if(word[0] == 0){return 0;}
	if(p_tree->p_node==NULL){
		p_tree->p_node = (node *)malloc(sizeof(node));
		p_tree->p_node->letter = word[0];
		p_tree->p_node->sibling.p_node = NULL;
		p_tree->p_node->son.p_node = NULL;
		if(word[1]==0){
			p_tree->p_node->offset = offset;
			return 0;
		}else{
			p_tree->p_node->offset = 0;
			return insertWord(&(p_tree->p_node->son), word+1, offset);
		}
	}else{
		if(p_tree->p_node->letter!=word[0]){
			return insertWord(&(p_tree->p_node->sibling), word, offset);
		}else{
			if(word[1]==0){
				if(p_tree->p_node->offset==0){
					p_tree->p_node->offset = offset;
					return 0;
				}
				else{return p_tree->p_node->offset;}
			}else{
				return insertWord(&(p_tree->p_node->son), word+1, offset);
			}
		}
	}
}
