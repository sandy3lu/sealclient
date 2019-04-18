package com.yunjing.eseal.tools;

import lombok.Data;

@Data
public class VerifyResult {

    String msg;
    int code;
    boolean verify;
    String reason;
}
