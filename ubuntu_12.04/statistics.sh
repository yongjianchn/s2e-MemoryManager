echo states
grep "Terminating\ state\ " $1 | wc -l
echo symb
grep "CS" $1 | wc -l
echo maybe0
grep "will\ \=\ 0" $1 | wc -l
echo time
grep "Terminating\ state\ 0\ with" $1 | cut -d ' ' -f 1
