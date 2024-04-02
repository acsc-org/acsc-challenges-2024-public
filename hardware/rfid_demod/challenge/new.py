import sys
import argparse
import numpy as np
from scipy.io.wavfile import write

def convert_to_wav(input_file, output_file):
    data = np.genfromtxt(input_file, delimiter=',', skip_header=1)
    time = data[:, 0]
    voltage = data[:, 1]
    # Save the audio file
    write(output_file, 1000000, voltage)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert data to WAV file")
    parser.add_argument("input_file", help="Path to the input data file")
    parser.add_argument("output_file", help="Path to the output WAV file")

    args = parser.parse_args()
    convert_to_wav(args.input_file, args.output_file)
