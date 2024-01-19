#include <iostream> 
#include <stack>
#include <Windows.h>
#include <ctime>
using namespace std;
template <typename Stack>
void dump_sort( Stack & input) {
    Stack tmpStack;

    while (input.size()!=0) {

        auto tmp = input.top();
        input.pop();

        while ((tmpStack.size()!=0) && (tmpStack.top() < tmp)) {
            input.push(tmpStack.top());
            tmpStack.pop();
        }

        tmpStack.push(tmp);
    }

    while (tmpStack.size()!=0) {
        input.push(tmpStack.top());
        tmpStack.pop();
    }
}

template<typename Stack>
void MovSt(Stack& src, Stack& dst) {
    while (src.size()) {
        dst.push(src.top());
        src.pop();
    }
}

template<typename Stack>
auto pop(Stack& s) {
    auto element = s.top();
    s.pop();
    return element;
}
template<typename Stack>
void mov_top_to(Stack& src, Stack& dst) {
    auto element = pop(src);
    dst.push(element);
}

template<typename Stack>
void qSortStack(Stack& inputStack)
{
    if (inputStack.size() < 2) {
        return;
    }
    Stack more;
    Stack less;
    Stack equal;
    Stack tmp;
    bool need_sort_less = false;
    bool need_sort_more = false;
    bool need_sort_lessu = false;
    bool need_sort_moreu = false;
    mov_top_to(inputStack, equal);

    while (inputStack.size())
    {
        auto element = pop(inputStack);


        if (element == equal.top())
        {
            equal.push(element);
        }
        else if (element > equal.top())
        {
            if (more.size()) {
                auto elem1 = more.top();
                if (elem1 < element) {
                    need_sort_more = true;
                }
                if (elem1 > element) {
                    need_sort_moreu = true;
                }
            }
            
            more.push(element);
        }
        else
        {
            if (less.size()) {
                   auto elem2 = less.top();
                    if (elem2 < element) {
                    need_sort_less = true;
                    }
                    if (elem2 > element) {
                        need_sort_lessu = true;
                    }
            }
           
            less.push(element);
        }
    }

    if (need_sort_more && need_sort_moreu) {
        qSortStack(more);
    }
    if(need_sort_less && need_sort_lessu){
        qSortStack(less);
    }
    
    if (!need_sort_moreu) {
        MovSt(more, inputStack);
        MovSt(equal, inputStack);
    }
    else {
       MovSt(more, equal);
       MovSt(equal, inputStack);
    }
    
    if (!need_sort_lessu) {
        MovSt(less, inputStack);
    }
    else {
        MovSt(less, equal);
       MovSt(equal, inputStack);
    }
       
      
    
    

}

template<typename Stack>
void merge(Stack& s1, Stack& s2, Stack& dst) {
    while ((s1.size()) && (s2.size())) {

        if ((s1.top()) < (s2.top())) {
            auto mov = pop(s1);
            dst.push(mov);
        }
        else {
            auto mov = pop(s2);
            dst.push(mov);
        }
    }
    while (s1.size()) {
        auto mov = pop(s1);
        dst.push(mov);
    }
    while (s2.size()) {
        auto mov = pop(s2);
        dst.push(mov);
    }
    return;
}
template<typename Stack>
void merge_sort(Stack& stack) {
    if (stack.size() < 2) {
        return;
    }
    Stack half1;
    Stack half2;
    Stack tmp;
    uint64_t half_size = (stack.size()) / 2;

    for (int i = 0; i < half_size; i++) {
        half1.push(pop(stack));
    }
    while (stack.size()) {
        half2.push(pop(stack));
    }
    
    merge_sort(half1);
    merge_sort(half2);
    merge(half1, half2, tmp);
    MovSt(tmp, stack);
    
}


template<typename Stack>
void merge_sort2(Stack& stack) {
    size_t st_size = stack.size(); 
    Stack half1;
    Stack half2;
    Stack tmp;
    size_t size;
    if (st_size < 2) {
        return;
    }
  
    do {
        
        if (stack.size()) {
            mov_top_to(stack, half1);
            while (half1.top() > stack.top()) {
                mov_top_to(stack, half1);
                if (!stack.size()) break;
            }
        }
        
        if (stack.size()) {
            mov_top_to(stack, half2);

            while (half2.top() > stack.top()) {
                mov_top_to(stack, half2);
                if (!stack.size()) break;
            }
        }
        
        merge(half1, half2, tmp);
        size = tmp.size();
        MovSt(tmp, half1);
        MovSt(half1, stack);
    
    } while (size < st_size);
    return;
}


template <typename F>
DWORD exec_time(F f) {
    DWORD s = GetTickCount64();
    f();
    return GetTickCount64() - s;
}
int main() {
    stack<int> input, input2, dst;
    
 srand(time(nullptr));
     for (int i = 0; i < 10; i++) {
         input2.push(rand());
     }
    // merge_sort(input2);
     DWORD a = exec_time([&]() {merge_sort2(input2); });
     cout << a << "  msec merge_sort with random" << endl;
     while (input2.size()) {
         cout << input2.top() << " ";
         input2.pop();
     }
     

     return(0);
}