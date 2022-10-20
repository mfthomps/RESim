PATCH1=e2fsismounted.patch  
PATCH2=e2fsprogs-debufs.c.patch  
PATCH3=e2fsprogs-debufs.h.patch  
PATCH4=e2fsprogs-devname.patch  
PATCH5=e2fsprogs-makefile.patch

git apply -p1 ../$PATCH1
git apply -p1 ../$PATCH2
git apply -p1 ../$PATCH3
git apply -p1 ../$PATCH4
git apply -p1 ../$PATCH5
echo "applied five patches"

