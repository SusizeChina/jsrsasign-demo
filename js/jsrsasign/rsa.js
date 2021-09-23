import "../base64/base64.js"
import "../jsrsasign/jsrsasign-all-min.js"

const ALGORITHM = 'SHA1withRSA';
/**
 * 应该从后台接口中获取
 * @returns {*}
 */
const getPrivateKey = () => {
  // base64之后的私钥
  let privateKey = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUNlQUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQW1Jd2dnSmVBZ0VBQW9HQkFQZGRKM1BVeWZOck1FUTMKa281OVBIUWpKVWxubkJ2bnVLeXNLNGNPR2RoZkMyWjJGQnFXQWdqUitqTjU0V2t5a0MrV2VZY0xXU2xidGRVYQo5bWN2SGR0WnNJUnQvNmt4SmJpU1pDNGo3bHpGRlFsc0tYdXgxbzRNR3NnMkFSRWM4Z0pVTFh3QWt0T0VSVXdmCktPNUhvbWZqTkNiSmcxdEY1S1MxajhHc1ZPOHhBZ01CQUFFQ2dZRUE2ZUcxSk1yajYzakVtU3RtTWIxdHhHMWEKbXU0UTV6MlFHZ3RyMkhWWHNJSWxHRXE2dFd4eUhmN1RMNHFrdXo5b251WUtuOG4yRXFtNDRmWnRWYUJ4KzVFUwp6UnBJdmxUdmF4bVZ1MEhaMWhZQXpVdzFYeVJuWE5NS3BMNXRUNEdDam04K1FHUHpsR3hnWEkxc05nOHI5SmF3Cjl6UlVZZUE2TFFSOVJJTWtIV1VDUVFEOFFvampWb0dqdGl1bm9oL044aXBsaFVzelpJYXZBRXZtRElFK2tWeSsKcEE3aHZsdWtMdzZKTWM3Y2ZUY25IeXhEbzlpSFZJenJXbFR1S1JxOUtXVkxBa0VBK3dnSlMyc2d0bGRuQ1ZuNgp0SktGVndzSHJXaE1JVTI5bXNQUGJOdVdVRDIzQmNLRS92ZWhJeUZ1MWFoTkEvVGlNNDBQRW56cHJRNUpmUHhVCjE2Uzc4d0pBTlRmTUxUbll5N0xvN3NxVEx4MkJ1RDB3cWp6dzlRWjQvS1Z5dHNKdjhJQW42NVAvUFZuNEZSVisKOEtFeCszem1GN2IvUFQybkpSZS9oeWNBenh0bWxRSkJBTXJGd1F4RXFwWGZvQUV6eDRsWTJaQm4vbm1hUi9TVwo0Vk5FWENib2NWQzdxVDFqMVI1SFZNZ1YxM3VLaVR0cThkVUdXbWhxc2k3eDNYYXlOSzVFQ1BVQ1FRRFphQU42CnR2SUhBcHo5T0xzWFN3MGpaaXJRNktFWWRoYXJYYklWRHkxVzFzVkUzbHpMYnFMZEZwMWJ4QUhRSXZzWVM1UE0KQTl2ZVNKaDM3MlJMSktragotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0t";
  return Base64.decode(privateKey)
}

const getPublicKey = () => {
  // base64之后的公钥
  let publicKey = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEM1hTZHoxTW56YXpCRU41S09mVHgwSXlWSgpaNXdiNTdpc3JDdUhEaG5ZWHd0bWRoUWFsZ0lJMGZvemVlRnBNcEF2bG5tSEMxa3BXN1hWR3Zabkx4M2JXYkNFCmJmK3BNU1c0a21RdUkrNWN4UlVKYkNsN3NkYU9EQnJJTmdFUkhQSUNWQzE4QUpMVGhFVk1IeWp1UjZKbjR6UW0KeVlOYlJlU2t0WS9CckZUdk1RSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==";
  return Base64.decode(publicKey)
}

//排序的函数
export const sortSignFiled = (obj) => {
  //先用Object内置类的keys方法获取要排序对象的属性名数组，再利用Array的sort方法进行排序
  var newkey = Object.keys(obj).sort();
  console.log('newkey=' + newkey);
  var newObj = ''; //创建一个新的对象，用于存放排好序的键值对
  for (var i = 0; i < newkey.length; i++) {
    //遍历newkey数组
    newObj += [newkey[i]] + '=' + obj[newkey[i]] + '&';
  }
  //追加时间搓
  newObj += "timestamp=" + Date.now();
  return newObj.substring(0, newObj.length - 1);
}

/**
 * 私钥签名
 * rsa 用 SHA1withRSA 算法签名
 * @param src 明文
 * @return {*}
 * @constructor
 */
export const rsaSign = (src) => {
  const signature = new KJUR.crypto.Signature({'alg': ALGORITHM});
  const priKey = KEYUTIL.getKey(getPrivateKey()); // 因为后端提供的是pck#8的密钥对，所以这里使用 KEYUTIL.getKey来解析密钥
  signature.init(priKey); // 初始化实例
  signature.updateString(src); // 传入待签明文
  const a = signature.sign(); // 签名, 得到16进制字符结果
  return hex2b64(a) // 转换成base64
}

/**
 * 公钥验签
 * @param src 明文
 * @param data 经过私钥签名并且转换成base64的结果
 * @return {Boolean} 是否验签成功
 * @constructor
 */
export const rsaVerifySign = (src, data) => {
  const signature = new KJUR.crypto.Signature({'alg': ALGORITHM, 'prvkeypem': getPublicKey()});
  signature.updateString(src); // 传入待签明文
  return signature.verify(b64tohex(data))
}
