target=`gcc -dumpmachine | gawk -F- '{print $1}'`
make clean && make
rm -rf ./bin/$target/*.exe
mkdir -p ./bin/$target
find . -name \*.exe -not -path "./bin/*" -exec cp -rf {} ./bin/$target/ \;
