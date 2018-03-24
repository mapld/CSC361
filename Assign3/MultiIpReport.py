from IpReport import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Read multiple cap files and produce relevant statistics')

    parser.add_argument('-l','--list', nargs='+', help='<Required> Set flag', required=True)
    fnames = parser.parse_args()._get_kwargs()[0][1]
    data = []
    for fname in fnames:
        data.append(reportOnFile(fname))

    print("\n")

    table_box_width = 18
    table_format_str = '{:<' + str(table_box_width) + '}'
    print(table_format_str.format(""), end='')
    for i in range(len(data)):
       print(table_format_str.format("Trace " + str(i+1)), end='')

    print(table_format_str.format("\n" + "Probes per ttl"), end='')
    for d in data:
       ttl_count = d['ttl_probe_count']
       print(table_format_str.format(ttl_count), end='')

    print("\n")

    diff_map = {}
    for i in range(len(data)):
       for j in range(len(data)):
           if i != j:
               intermediate_set_1 = data[i]['intermediate_ips']
               intermediate_set_2 = data[j]['intermediate_ips']
               diffs = intermediate_set_1 - intermediate_set_2
               for diff in diffs:
                   if diff not in diff_map:
                       diff_map[diff] = set()
                   diff_map[diff].add(i+1)

    all_nums = set(range(1,len(data)+1))
    for diff in diff_map:
        traces_with = diff_map[diff]
        print("Router with IP " , diff, "found in traces ", str(traces_with), "and not found in", str(all_nums-traces_with))

    if(len(diff_map) == 0):
        print("The intermediate routers match in all trace files")

        table_box_width = 18
        table_format_str = '{:<' + str(table_box_width) + '}'
        float_format_str = '{:4.3f}'
        print(table_format_str.format("TTL"), end='')
        for i in range(len(data)):
            print(table_format_str.format("Trace " + str(i+1)), end='')

            for j in range(len(data[0]['rtt_means'])):
                # print("")
                print("")
                print(table_format_str.format(j),end='')
                for i in range(len(data)):
                    d = data[i]
                    if(len(d['rtt_means'])-1 < j):
                        continue
                    rtt_mean = d['rtt_means'][j]
                    print(table_format_str.format(float_format_str.format(rtt_mean)), end='')
