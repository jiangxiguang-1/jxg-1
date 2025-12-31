#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>
#include <openssl/sha.h>


/* @brief check if the auth.key is existsed
 */
bool file_exists(const char *auth_key) {
    struct stat buffer;

    if (stat(auth_key, &buffer) == 0) {
        return true;
    } else {
        return false;
    }
}

#if 0
/* @brief because many devices cannot get the cpuid,
 * the product serial is used instead
 */
int get_x86_64_cpuid(char **cpuid) {
    FILE *pipe;
    char cmd[1024];
    char buffer[1024];

    sprintf(cmd, "sudo dmidecode -s system-serial-number");

    pipe = popen(cmd, "r");
    if (pipe == NULL) {
        printf("failed to run dmidecode cmd\n");
        return 1; //no root permisson
    }

    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        printf("serial num:%s\n", buffer);
	*cpuid = buffer;
    }

    pclose(pipe);

    if (*cpuid == NULL) {
        return 2; //failed to read CPUID
    }

    printf("cpuid:%s\n",*cpuid);
    
    return 0;
}
#endif

/* @breaf because the devices may have the same product serial number,
 * the hdparm /dev/sda5 serial number is used instead
 */
int get_x86_64_cpuid(char **cpuid) {
    FILE *pipe;
    char cmd[1024];
    char buffer[1024];

    sprintf(cmd, "sudo hdparm -I /dev/sda5 | grep 'Serial Number'");

    pipe = popen(cmd, "r");
    if (pipe == NULL) {
        printf("failed to run hdparm cmd");
        return 1; //no root permisson
    }

    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        printf("serial num:%s\n", buffer);
        *cpuid = buffer;
        *cpuid += 20; //cross over 'Serial Number' and the colon and the space
    }

    pclose(pipe);

    if (*cpuid == NULL) {
        return 2; //failed to read hdparm info
    }

    printf("cpuid:%s\n", *cpuid);

    return 0;
}


/* @brief get arm64 Serial for cpuid
 */
int get_arm64_cpuid(char **cpuid) {
    FILE *fp;
    char buffer[1024] = {0};

    *cpuid = buffer;

    fp = fopen("/proc/cpuinfo", "r");
    if (fp == NULL) {
        printf("failed to open /proc/cpuinfo\n");
        return 1; //no root permisson
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strncmp(buffer, "Serial", 6) == 0) {
	    *cpuid = buffer;
	    if (*cpuid != NULL) {
                *cpuid += 10; //cross over the colon and the space
                printf("CPU serial number:%s\n", *cpuid);
                break;
	    }
	}
    }

    fclose(fp);

    if (*cpuid == NULL) {
        return 2; //failed to read CPUID
    }

    return 0;
}

#if 0
/* @brief get kylin CPUID
 */
int get_kylin_cpuid(char *cpuid) {

}
#endif

/* @brief get CPUID type by uname cmd
 */
int get_cpu_type() {
    FILE *fp;
    char buffer[1024];

    fp = popen("uname -m", "r");
    if (fp == NULL) {
        printf("failed to run uname cmd\n");
        return -1;
    }

    fgets(buffer, sizeof(buffer), fp);
    pclose(fp);

    //remove line feed
    buffer[strcspn(buffer, "\n")] = 0;

    if (strcmp(buffer, "x86_64") == 0) {
        printf("it is x86_64 architecture\n");
        return 1;
    } else if ((strcmp(buffer, "aarch64") == 0) ||
	       (strcmp(buffer, "arm64") == 0)) {
        printf("it is arm64 architecture\n");
        return 2;
    } else {
        printf("unknown architecture\n");
        return -1;
    }
}

#if 0
/* @brief remove special chars in cpuid
 */
void remove_special_chars(char *cpuid) {
    int i, j = 0;

    while (cpuid[j]) {
        if (isalnum((unsigned char)cpuid[j])) {
	    cpuid[i++] = cpuid[j]; //cover special char
	}
	j++; //move to the next char
    }
    cpuid[i] = '\0';

    return;
}
#endif


/* @brief change letter to lower case
*/
void change_to_lowercase(char *cpuid) {
    while (*cpuid) {
        if (isupper((unsigned char)*cpuid)) {
	    *cpuid = tolower((unsigned char)*cpuid);
	}

	cpuid++; //move to the next char
    }

    return;
}

/* @brief hash cpuid with sha-256
 */
void hash_sha256(const char *cpuid, unsigned char *hash) {
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, cpuid, strlen(cpuid));
    SHA256_Final(hash, &sha256);


    printf("the cpuid value:%s and the hash value:%s\n",cpuid, hash);

    return;
}

/* @brief save cpuid to auth.key
 */
int save_cpuhash_to_key(unsigned char *hash) {
    FILE *fp;
    char file_path[256];

    if (mkdir("/etc/auth_check", 0755) == -1) {
        printf("failed to create /etc/auth_check path\n");
        return -1;
    }

    snprintf(file_path, sizeof(file_path), "/etc/auth_check/auth.key");

    fp = fopen("/etc/auth_check/auth.key", "w");
    if (fp == NULL) {
        printf("failed to open auth.key\n");
        return -1;
    }

    if (fprintf(fp, "%s\n", hash) < 0) {
        printf("failed to save the cpuhash\n");
        fclose(fp);
        return -1;
    }

    fclose(fp);

    printf("save cpuhash key seccessful\n");

    return 0;
}

/* @breaf check new hash with old hash
 */
bool auth_module_check(unsigned char *hash) {
    FILE *fp;
    unsigned char buffer[SHA256_DIGEST_LENGTH];

    fp = fopen("/etc/auth_check/auth.key", "r");
    if (fp == NULL) {
        printf("failed to open the auth.key\n");
        return false;
    }

    (void)fread(buffer,sizeof(unsigned char), SHA256_DIGEST_LENGTH, fp);

    fclose(fp);

    if (memcmp(buffer, hash, SHA256_DIGEST_LENGTH) == 0) {
        printf("auth module check seccessful\n");
    } else {
	printf("failed to auth check\n");
        return false;
    }

    return true;
}



/* @brief init the module of geting CPUID and auth
 */
int auth_module_init() {
    int ret = 0;
    char *cpuid = NULL;
    bool is_key_existed = false;
    bool is_key_matched = true;
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};

    ret = get_cpu_type();
    if (ret == -1) {
        return 2; //read CPU type failed
    } else if (ret == 1) {
        ret = get_x86_64_cpuid(&cpuid);
	if (ret == 1) {
	    return 1; //no root permisson
	} else if (ret == 2) {
	    return 2; //read CPUID failed
	}
    } else if (ret == 2) {
        ret = get_arm64_cpuid(&cpuid);
	if (ret == 1) {
	    return 1; //no root permisson
	} else if (ret == 2) {
	    return 2; //read CPUID failed
	}
    }

    //remove_special_chars(cpuid);
    change_to_lowercase(cpuid);
    hash_sha256(cpuid, hash);

    is_key_existed = file_exists("/etc/auth_check/auth.key");
    if (is_key_existed) {
        //check new CPUID with existed CPUID
        is_key_matched = auth_module_check(hash);
	if (is_key_matched != true) {
	    printf("auth key failed");
	    exit(-1);
	}
    } else {
        ret = save_cpuhash_to_key(hash);
	if (ret != 0) {
	    return 3; //cave new CPUID failed
	}
    }

    return 0;
}

/* @brief destroy the auth software and free resource
 */
void auth_module_destroy() {
    return;
}

int main() {
    int ret = 0;

    ret = auth_module_init();
    if (ret == 0) {
        printf("auth_module_init successful\n");
    } else if (ret == 1) {
        printf("no permission for auth check\n");
	exit(1);
    } else if (ret == 2) {
        printf("failed to read CPUID\n");
        exit(2);
    } else if (ret == 3) {
        printf("failed to write auth_key\n");
	exit(3);
    } else {
        printf("other errors\n");
        exit(-1);
    }

    auth_module_destroy();

    return 0;
}
