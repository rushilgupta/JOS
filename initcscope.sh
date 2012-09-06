PROJECT_DIR=/home/naresh/cse506/lab
cd /
find $PROJECT_DIR -name '*.c' -o -name '*.h' > $PROJECT_DIR/cscope.files
cd $PROJECT_DIR
cscope -b
export CSCOPE_DB=$PROJECT_DIR/cscope.out
