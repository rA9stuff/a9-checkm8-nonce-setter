//
//  main.m
//  a9-checkm8-nonce-setter
//
//  Created by rA9stuff on 8.10.2021.
//

#import <Foundation/Foundation.h>
#include "libirecovery.h"
#include <unistd.h>

uint64_t ecid = 0;
bool supported = false;
bool pwned = false;
int runs = 0;
NSString *cpid = @"";

irecv_device_t device = NULL;
irecv_client_t client = NULL;

void downloadBootchain (void) {

    NSTask *dl = [[NSTask alloc] init];
    dl.launchPath = @"/usr/bin/curl";
    dl.arguments = @[@"-Lo", @"a9bc.zip", @"https://drive.google.com/uc?export=download&id=170rPMRkXNAgMO7bWWPQ97A0UBahwdmPT"];
    [dl launch];
    [dl waitUntilExit];

    NSTask *unzip = [[NSTask alloc] init];
    unzip.launchPath = @"/usr/bin/unzip";
    unzip.arguments = @[@"a9bc.zip"];
    [unzip launch];
    [unzip waitUntilExit];
}

NSString* NSCPID(const unsigned int *buf) {
    NSMutableString *ms=[[NSMutableString alloc] init];
    for (int i = 0; i < 1; i++) {
        [ms appendFormat:@"%04x", buf[i]];
    }
    return ms;
}

NSString* NSNonce(unsigned char *buf, size_t len) {
    NSMutableString *nonce=[[NSMutableString alloc] init];
    for (int i = 0; i < len; i++) {
        [nonce appendFormat:@"%02x", buf[i]];
    }
    return nonce;
}

int sendFile(const char *filename) {
    
    irecv_send_file(client, filename, 1);
    return 0;
}

int reconnect(void) {
    
    bool connected = false;
    
    while (!connected) {
        irecv_error_t erro = irecv_open_with_ecid(&client, ecid);
        if (runs == 0) {
            printf("Waiting for an A9 device in DFU Mode... \n");
            runs++;
        }
        if (erro == IRECV_E_UNSUPPORTED) {
            fprintf(stderr, "ERROR: %s\n", irecv_strerror(erro));
            return -2;
        }
        else if (erro != IRECV_E_SUCCESS) {
            usleep(500000);
        }
        else {
            connected = true;
        }
    }
    
    return 0;
}

int Discover(void) {
    
    reconnect();
    
    irecv_devices_get_device_by_client(client, &device);
    const struct irecv_device_info *devinfo = irecv_get_device_info(client);
    if (!devinfo -> srtg) {
        printf("Device connected in wrong mode, exiting\n");
        exit(-1);
    }
    cpid = NSCPID(&devinfo -> cpid);
    const char *charCPID = [cpid cStringUsingEncoding:NSASCIIStringEncoding];
    if (strcmp(charCPID, "8000") == 0 || strcmp(charCPID, "8003") == 0) {
        supported = true;
        NSString *serialString = [NSString stringWithFormat:@"%s", devinfo -> serial_string];
        if ([serialString containsString:@"PWND"]) {
            pwned = true;
        }
    }
    irecv_close(client);
    return 0;
}

void printDevInfo(const struct irecv_device_info *devinfo) {
    
    NSString *devname = [NSString stringWithFormat:@"%s", device -> display_name];
    NSString *boardname = [NSString stringWithFormat:@"%s", device -> hardware_model];
    printf("Device Model: %s\n", [devname cStringUsingEncoding:NSASCIIStringEncoding]);
    printf("Board Config: %s\n", [boardname cStringUsingEncoding:NSASCIIStringEncoding]);
    printf("APNonce: %s \n", [NSNonce(devinfo -> ap_nonce, devinfo -> ap_nonce_size) cStringUsingEncoding:NSASCIIStringEncoding]);
}

int exploit(void) {
    NSString *eclipsa = [@"a9bc/eclipsa" stringByAppendingString:cpid];
    NSTask *exploit = [[NSTask alloc] init];
    exploit.launchPath = eclipsa;
    [exploit launch];
    [exploit waitUntilExit];
    
    return 0;
}

int setNonce(const struct irecv_device_info *devinfo, NSString *nonce) {

    int ret, mode;
    ret = irecv_get_mode(client, &mode);
    NSString *devicemodel = [NSString stringWithFormat:@"%s", device ->hardware_model];
    devicemodel = [devicemodel stringByAppendingString:@".img4"];
    NSString *ibssfile = [@"a9bc/" stringByAppendingString:[@"iBSS." stringByAppendingString:devicemodel]];
    NSString *ibecfile = [@"a9bc/" stringByAppendingString:[@"iBEC." stringByAppendingString:devicemodel]];
    NSString *bootnoncecommand = [@"setenv com.apple.System.boot-nonce " stringByAppendingString:nonce];
    sendFile([ibssfile cStringUsingEncoding:NSASCIIStringEncoding]);
    sleep(2);
    reconnect();
    sendFile([ibecfile cStringUsingEncoding:NSASCIIStringEncoding]);
    sleep(2);
    reconnect();
    irecv_send_command(client, "bgcolor 255 0 0");
    usleep(500000);
    irecv_send_command(client, [bootnoncecommand cStringUsingEncoding:NSASCIIStringEncoding]);
    irecv_send_command(client, "saveenv");
    irecv_send_command(client, "setenv auto-boot false");
    irecv_send_command(client, "saveenv");
    irecv_send_command(client, "reset");
    irecv_close(client);
    return 0;
}

void printUsage(void) {
    printf("Usage: a9noncesetter [your desired generator]\n");
    printf("(leave empty for 0x1111111111111111)\n");
    printf("e.g. a9noncesetter 0x6cac2d8197738a56\n");
}


int main(int argc, const char * argv[]) {
    
    if (argc > 2) {
        printf("Invalid input\n");
        printUsage();
        exit(-1);
    }
        
    else if (argc == 2) {
        if (strlen(argv[1]) != 18 && strlen(argv[1]) != 0) {
            printf("Invalid input\n");
            printUsage();
            exit(-1);
        }
    }
    
    NSString *bootnonce = @"";
    if (argc == 1) {
        printf("No generator given, using the default 0x1111111111111111\n");
        bootnonce = @"0x1111111111111111";
    }
    else {
        bootnonce = [NSString stringWithUTF8String:argv[1]];
    }
    
    if (Discover() == 0) {
        if (supported) {
            system("killall eclipsa8000 2> /dev/null");
            system("killall eclipsa8003 2> /dev/null");
            NSFileManager *filemanager = [[NSFileManager alloc] init];
            NSString *currentPath = [filemanager currentDirectoryPath];
            if ([filemanager fileExistsAtPath:[currentPath stringByAppendingString:@"/a9bc"]]) {
                printf("Bootchain exists, skipping download \n");
            }
            else {
                printf("Bootchain not found in working directory, downloading it... \n");
                downloadBootchain();
                NSFileManager *check = [[NSFileManager alloc] init];
                if ([check fileExistsAtPath:[currentPath stringByAppendingString:@"/a9bc"]]) {
                    printf("Successfully downloaded bootchain \n");
                }
                else {
                    printf("An error occurred downloading bootchain, exiting \n");
                    exit(-1);
                }
            }
            printf("Device is supported \n");
            if (pwned) {
                printf("Device is pwned, skipping eclipsa \n");
            }
            else {
                printf("Device is NOT pwned, exploiting with eclipsa \n");
                exploit();
            }
            reconnect();
            irecv_devices_get_device_by_client(client, &device);
            const struct irecv_device_info *devinfo = irecv_get_device_info(client);
            printDevInfo(devinfo);
            printf("Setting apnonce\n");
            if (setNonce(devinfo, bootnonce) == 0) {
                printf("Apnonce should be set, rebooting in recovery mode \n");
            }
        }
        else {
            printf("This device is not supported, stopping here\n");
            exit(-1);
        }
    }
    else {
        printf("An error occured connecting to device\n");
        exit(-1);
    }
    return 0;
}

