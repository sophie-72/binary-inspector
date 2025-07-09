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
    
    // Test with command line arguments
    if (argc > 1) {
        printf("First argument: %s\n", argv[1]);
    }
    
    return 0;
} 
