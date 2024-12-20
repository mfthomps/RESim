Command line used to find this crash:

/home/mike/afl/AFL/afl-fuzz -i /home/mike/afl/seeds/cadet-tst -o /home/mike/afl/output/cadet-tst -S wer-7910_resim_2 -p 8701 -R cadet-tst

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 50.0 MB.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop
me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to
add your finds to the gallery at:

  http://lcamtuf.coredump.cx/afl/

Thanks :-)
