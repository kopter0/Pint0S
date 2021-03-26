int convert_to_fp(int n);
int convert_to_int_zero(int x);
int convert_to_int_nearest(int x);
int sum_fp(int x, int y);
int sub_fp(int x, int y);
int sum_fp_int(int x, int n);
int sub_fp_int(int x, int n);
int mul_fp(int x, int y);
int mul_fp_int(int x, int n);
int div_fp(int x, int y);
int div_fp_int(int x, int y);

const int f = (1 << 14);

int convert_to_fp(int n){
    return n * f;
}

int convert_to_int_zero(int x){
    return x / f;
}

int convert_to_int_nearest(int x){
    if (x >= 0){
        return (x + f / 2) / f;
    }else{
        return (x - f / 2) / f;
    }   
}

int sum_fp(int x, int y){
    return x + y;
}

int sub_fp(int x, int y){
    return x - y;
}

int sum_fp_int(int x, int n){
    return x + n * f;
}

int sub_fp_int(int x, int n){
    return x - n * f;
}

int mul_fp(int x, int y){
    return ((int64_t) x) * y / f;
}

int mul_fp_int(int x, int n){
    return x * n;
}

int div_fp(int x, int y){
    return ((int64_t) x) * f / y;
}

int div_fp_int(int x, int n){
    return x / n;
}