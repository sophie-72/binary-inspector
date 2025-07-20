#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global variables for testing
int global_counter = 0;
char* global_message = "Hello from global!";

// Simple function
int add_numbers(int a, int b) {
    return a + b;
}

// Function with if/else
int check_number(int num) {
    if (num > 0) {
        printf("Positive number: %d\n", num);
        return 1;
    } else if (num < 0) {
        printf("Negative number: %d\n", num);
        return -1;
    } else {
        printf("Zero\n");
        return 0;
    }
}

// Function with loops
void print_loop(int count) {
    int i;
    for (i = 0; i < count; i++) {
        printf("Loop iteration %d\n", i);
        global_counter++;
    }
    
    while (global_counter > 0) {
        printf("Global counter: %d\n", global_counter);
        global_counter--;
    }
}

// Function with switch statement
void process_choice(int choice) {
    switch (choice) {
        case 1:
            printf("Option 1 selected\n");
            break;
        case 2:
            printf("Option 2 selected\n");
            break;
        case 3:
            printf("Option 3 selected\n");
            break;
        default:
            printf("Invalid option\n");
            break;
    }
}

// Function with nested control flow
int complex_logic(int x, int y) {
    int result = 0;
    
    if (x > 10) {
        if (y < 5) {
            result = x + y;
        } else {
            result = x - y;
        }
    } else {
        for (int i = 0; i < x; i++) {
            result += i;
        }
    }
    
    return result;
}

// Recursive function: factorial
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

// Function pointer test
void call_func_ptr(int (*func)(int, int)) {
    int res = func(2, 3);
    printf("Func ptr result: %d\n", res);
}

// Struct and array test
struct Point { int x, y; };
void struct_test() {
    struct Point p = {1, 2};
    int arr[3] = {10, 20, 30};
    printf("Point: %d %d, Array: %d %d %d\n", p.x, p.y, arr[0], arr[1], arr[2]);
}

// Local variable scope test
void local_var_test() {
    int a = 1;
    if (a) {
        int b = 2;
        printf("Inner b: %d\n", b);
    }
    // Uncommenting the next line should cause a compile error (b is out of scope)
    // printf("Outer b: %d\n", b);
}

// String and memory operation test
void string_test() {
    char buf[20];
    strcpy(buf, "test");
    printf("Buffer: %s\n", buf);
}

// Empty function
void empty_function() {}

// Return-only function
int return_only() { return 42; }

// Unreachable code
void unreachable_code() {
    return;
    printf("This should not be printed!\n");
}

// Main function with various patterns
int main(int argc, char* argv[]) {
    printf("Binary Inspector Test Program\n");
    printf("Global message: %s\n", global_message);
    
    // Test function calls
    int sum = add_numbers(5, 3);
    printf("Sum: %d\n", sum);
    
    // Test if/else
    check_number(10);
    check_number(-5);
    check_number(0);
    
    // Test loops
    print_loop(3);
    
    // Test switch
    process_choice(2);
    process_choice(5);
    
    // Test complex logic
    int result = complex_logic(15, 3);
    printf("Complex result: %d\n", result);
    
    // Recursion
    int fact = factorial(5);
    printf("Factorial(5): %d\n", fact);

    // Function pointer
    call_func_ptr(add_numbers);

    // Struct/array
    struct_test();

    // Local variable scope
    local_var_test();

    // String/memory
    string_test();

    // Edge-case functions
    empty_function();
    int ret = return_only();
    printf("Return-only: %d\n", ret);
    unreachable_code();
    
    // Test with command line arguments
    if (argc > 1) {
        printf("First argument: %s\n", argv[1]);
    }
    
    return 0;
} 
