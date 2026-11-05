set pagination off
set confirm off
break main
run
break BUF_MEM_grow_clean if len >= 16000
continue
printf "HIT 1: BUF_MEM_grow_clean(str->max=%lu, len=%lu) -> allocation will be (len+3)/3*4 = %lu bytes\n", str->max, len, (len+3)/3*4
bt 6
continue
printf "HIT 2: BUF_MEM_grow_clean(str->max=%lu, len=%lu)\n", str->max, len
bt 6
continue
