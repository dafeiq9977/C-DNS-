#ifndef TREE_H_
#define TREE_H_
struct node;
typedef struct
{
    struct node *p_node;
}tree;
typedef struct node 
{
    char letter;
    int offset;
    tree sibling;
    tree son;
}node;

void initTree(tree *p_tree);
void destroyTree(tree *p_tree);
int insertWord(tree *p_tree, char *word, int offset);
#endif