import frida
import os
import sys

def output_handler(pid, fd, data):
  sys.stdout.buffer.write(data)

def main():
  device = frida.get_local_device()
  pid = device.spawn(['./prog'], stdio='pipe')

  device.on('output', output_handler)
  process = frida.attach(pid)

  with open('inst.js', 'r') as f:
    inst = f.read()

  script = process.create_script(inst)

  def on_message(message, data):
      if message['type'] == 'send' and message['payload'] == 'give_me_maps':
        with open('/proc/{}/maps'.format(pid)) as f:
          maps = f.read()
  
        ranges = []
        for line in maps.split('\n'):
          if not line: continue
  
          if 'rwxp' in line:
            beg, end = [int(i, 16) for i in line.split(' ')[0].split('-')]
            ranges.append([beg, end])
  
        script.post({'type': 'give_me_maps_reply', 'payload': ranges})

  script.on('message', on_message)
  script.load()

  frida.resume(pid)

  try:
    while 1:
      c = sys.stdin.buffer.read(1)
      device.input(pid, c)
  except:
    pass
  
  try:
    os.waitpid(pid, 0)
  except:
    pass

if __name__ == '__main__':
  main()
