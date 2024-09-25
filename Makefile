pcap_ex: pcap_ex.o
	gcc -o pcap_ex pcap_ex.o -lpcap

pcap_ex.o: pcap_ex.c
	gcc -c pcap_ex.c

clean:
	rm *.o pcap_ex *.txt
