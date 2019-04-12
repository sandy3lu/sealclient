package com.yunjing.eseal.tools;

import lombok.Data;

@Data
public class SealSignInput {


    int signMethod;
    /** URL Base64 编码的证书 */
    String urlBase64cert;

    /** 用户的访问token */
    String token;

    /** URL Base64 编码的文件 */
    String urlBase64InData;

    /**
     *  是否盖在pdf上,false不盖，返回值中只包括签章数据
     * */
    boolean sealPDF=false;
}
