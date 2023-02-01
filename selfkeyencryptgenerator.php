<?php
//run: https://service.unisayogya.ac.id/selfkeyencryptgenerator.php
//generate selfkeyencrypt class
$randomString='D,';$characters='Yy';$randomString.=$characters[rand(0, strlen($characters) - 1)];$characters='- ';$randomString.=$characters[rand(0, strlen($characters) - 1)];$characters='FMmn';$randomString.=$characters[rand(0, strlen($characters) - 1)];$characters='- ';$randomString.=$characters[rand(0, strlen($characters) - 1)];$characters='jd';$randomString.=$characters[rand(0, strlen($characters) - 1)];
echo "
class selfkeyencrypt
{
    //https://www.php.net/manual/en/function.openssl-encrypt.php
    private \$keydigit_;
    private \$method_        = 'aes-256-cbc';
    private \$length_        = 5;
    private \$isdate_        = true;
    
    private \$salt_          = '".base64_encode(bin2hex(random_bytes(40)))."'; //echo base64_encode(bin2hex(random_bytes(40)));
    private \$sign_          = ".(rand() % 2 ? -1 : 1).";         //echo rand() % 2 ? -1 : 1;
    private \$days_          = ".rand(1, 300).";        //echo rand(1, 300);
    private \$x_             = ".rand(1, 999999).";     //echo rand(1, 999999);
    private \$y_             = ".rand(1, 999999).";     //echo rand(1, 999999);
    private \$dateformat_    = '".$randomString."';  //\$randomString='D,';\$characters='Yy';\$randomString.=\$characters[rand(0, strlen(\$characters) - 1)];\$characters='- ';\$randomString.=\$characters[rand(0, strlen(\$characters) - 1)];\$characters='FMmn';\$randomString.=\$characters[rand(0, strlen(\$characters) - 1)];\$characters='- ';\$randomString.=\$characters[rand(0, strlen(\$characters) - 1)];\$characters='jd';\$randomString.=\$characters[rand(0, strlen(\$characters) - 1)];echo \$randomString;
    
    function generatekeydigit_()
    {
        \$this->keydigit_ = rand(10 ** (\$this->length_-1), (10 ** \$this->length_) - 1);
    }
    
    function datefactor_()
    {
        return \$this->isdate_ ? date(preg_replace('/[^(FMmnjdDYy\-\s)]/', \$this->dateformat_), strtotime(((\$this->sign_ == -1)?'-':'').\$this->days_.' days')) : '';
    }
    
    function keyfactor_()
    {
        return (\$this->keydigit_ ** 2) + (\$this->sign_ * \$this->x_ * \$this->keydigit_) + \$this->y_;
    }
    
    function key_(\$kd = '')
    {
        if (\$kd == '') 
          \$this->generatekeydigit_();
        else
          \$this->keydigit_ = \$kd;
        return base64_encode(\$this->datefactor_().\$this->keyfactor_().\$this->salt_);
    }
    
    function encrypt_(\$data)
    {
        \$iv_length      = openssl_cipher_iv_length(\$this->method_);
        \$iv             = openssl_random_pseudo_bytes(\$iv_length);
        \$k              = \$this->key_();
        \$ciphertext_raw = openssl_encrypt(\$data, \$this->method_, \$k, OPENSSL_RAW_DATA , \$iv);
        \$hmac           = hash_hmac('sha256', \$ciphertext_raw, \$k, \$as_binary=true);
        return base64_encode( \$iv.\$hmac.\$ciphertext_raw ).\$this->keydigit_;

    }
    
    function decrypt_(\$data)
    {
        \$kd             = substr(\$data, -\$this->length_);
        \$mix            = base64_decode(substr(\$data, 0, strlen(\$data) - \$this->length_));
        \$iv_length      = openssl_cipher_iv_length(\$this->method_);
        \$iv             = substr(\$mix, 0, \$iv_length);
        \$k              = \$this->key_(\$kd);
        \$hmac           = substr(\$mix, \$iv_length, \$sha2len=32);
        \$ciphertext_raw = substr(\$mix, \$iv_length+\$sha2len);
        return openssl_decrypt(\$ciphertext_raw, \$this->method_, \$k, OPENSSL_RAW_DATA, \$iv);
    }
    
    /* getter setter */
    function getKeydigit()
    {
        return \$this->keydigit_;
    }
    
    function setKeydigit(\$kd)
    {
        \$this->keydigit_ = \$kd;
    }
}

//\$a = new selfkeyencrypt();
//\$data = \$a->encrypt_('test');
//echo \$a->decrypt_(\$data);
";
