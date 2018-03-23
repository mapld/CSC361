from IpReport import *

if __name__ == "__main__":
   parser = argparse.ArgumentParser(description='Read multiple cap files and produce relevant statistics')

   parser.add_argument('-l','--list', nargs='+', help='<Required> Set flag', required=True)
   fnames = parser.parse_args()._get_kwargs()[0][1]
   for fname in fnames:
       reportOnFile(fname)
