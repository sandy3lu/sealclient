package com.yunjing.eseal.tools;

import lombok.Data;

@Data
public class SealSignInput {


    int signMethod;
    String cert;
    String token;
    String inData;
}
