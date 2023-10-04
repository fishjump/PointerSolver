int main() {
  int *a = malloc(sizeof(int));
  *a = 1;

  return *a;
}