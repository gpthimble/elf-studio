int helper(int x) { return x * 3 + 1; }
int compute(int a, int b) {
  int s = 0;
  for (int i = 0; i < a; i++) s += helper(i) ^ b;
  return s - (b << 2);
}
long sum_bytes(const unsigned char *p, long n) {
  long s = 0;
  while (n--) s += *p++;
  return s;
}
