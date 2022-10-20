PATCH=../dtc-lexer.patch
git apply -p1 $PATCH || exit 1
echo "applied $PATCH"
