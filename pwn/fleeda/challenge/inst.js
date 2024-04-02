const main_address = DebugSymbol.fromName("main").address;
const main_func = new NativeFunction(
  main_address, "int", ["int", "pointer"],
  {
    traps: "all",
  });

function onDetected (context) {
  console.log('Detected');
}

function onDetected2 (context) {
  console.log('Detected 2');
}

function onDetected3 (context) {
  console.log('Detected 3');
}

function getBanRanges() {
  var ranges = null;

  while (ranges === null) {
    send('give_me_maps');
    const op = recv('give_me_maps_reply', 
                    value => {
                      ranges = value.payload;
                    });
    op.wait();
  }

  return ranges;
}

const main_wrapper = new NativeCallback(
  (argc, argv) => {
    var tid = Process.getCurrentThreadId();
    Stalker.follow(tid, {

      transform(iterator) {
        let instruction = iterator.next();

        while (instruction !== null) {
          if (instruction.mnemonic === 'syscall') {
            iterator.putCmpRegI32('eax', 1);
            iterator.putJccNearLabel('ja', 'l_banned', 'no-hint');
            iterator.putCmpRegI32('eax', 1);
            iterator.putJccNearLabel('je', 'l_do_syscall', 'no-hint');

            iterator.putAddRegReg('rdx', 'rsi');
            iterator.putCmpRegReg('rdx', 'rsi');
            iterator.putJccNearLabel('ja', 'l_check_ranges', 'no-hint');
            
            iterator.putCallout(onDetected);
            iterator.putBytes([0x0f, 0x0b]);

            iterator.putLabel('l_check_ranges');

            iterator.putPushReg('rax');
            iterator.putPushReg('rbx');

            const ranges = getBanRanges();

            for (const range of ranges) {
              const label_get_min = `l_get_min_rlim_${range[0]}`;
              const label_check = `l_check_intersect_${range[0]}`;
              const label_pass = `l_pass_${range[0]}`;

              // rax = max(rsi, range[0])
              iterator.putMovRegU64('rax', range[0]);
              iterator.putCmpRegReg('rsi', 'rax');
              iterator.putJccShortLabel('jbe', label_get_min, 'no-hint');
              iterator.putMovRegReg('rax', 'rsi');

              iterator.putLabel(label_get_min);

              // rbx = min(rdx, range[1])
              iterator.putMovRegU64('rbx', range[1]);
              iterator.putCmpRegReg('rdx', 'rbx');
              iterator.putJccShortLabel('jae', label_check, 'no-hint');
              iterator.putMovRegReg('rbx', 'rdx');

              iterator.putLabel(label_check);

              iterator.putCmpRegReg('rbx', 'rax');
              iterator.putJccShortLabel('jbe', label_pass, 'no-hint'); 

              iterator.putCallout(onDetected2);
              iterator.putBytes([0x0f, 0x0b]);

              iterator.putLabel(label_pass);
            }

            iterator.putPopReg('rbx');
            iterator.putPopReg('rax');
            iterator.putSubRegReg('rdx', 'rsi');

            iterator.putLabel('l_do_syscall');
            iterator.putBytes([0x0f, 0x05]);
            iterator.putJmpShortLabel('l_finish');

            iterator.putLabel('l_banned');
            iterator.putMovRegU64('rax', 0xffffffffffffffff);

            iterator.putLabel('l_finish');

            iterator.flush();
          } else if (instruction.address == 0x4011c6) {
            iterator.putPushReg('rdx');

            const ranges = getBanRanges();

            for (const range of ranges) {
              const label_ok = `l_ok_${range[0]}`;

              iterator.putMovRegU64('rdx', range[0]);
              iterator.putCmpRegReg('rbx', 'rdx');
              iterator.putJccShortLabel('jb', label_ok, 'no-hint');

              iterator.putMovRegU64('rdx', range[1]);
              iterator.putCmpRegReg('rdx', 'rbx');
              iterator.putJccShortLabel('jbe', label_ok, 'no-hint');

              iterator.putCallout(onDetected3);
              iterator.putBytes([0x0f, 0x0b]);

              iterator.putLabel(label_ok);
            }

            iterator.putPopReg('rdx');

            iterator.flush();
            iterator.keep();
          } else {
            iterator.keep();
          }
      
          instruction = iterator.next();
        }
      },
    });

    const ret = main_func(argc, argv);
    Stalker.unfollow(tid);
    Stalker.flush();

    return ret;
  },
  "int",
  ["int", "pointer"]
);

Interceptor.replace(main_address, main_wrapper);
