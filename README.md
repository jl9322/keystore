# Keystore

Non-Visible [Kodular](https://creator.kodular.io/) and [MIT App Inventor](https://appinventor.mit.edu/) component extension.

## Overview


Non-visible component extension to encrypt and decrypt user data using Android Keystore.


### Android Keystore

The Android Keystore is a system to perform cryptographic operations on the device in a more secure manner. The encryption keys are stored securely on the device and the encryption key is non-exportable. The encryption key is never exposed to the app. Visit this [Android developer documentation](https://developer.android.com/training/articles/keystore) for more information on the Android keystore.

## Methods

This extension has just two methods. One to encrypt user data and one to decrypt.

### Encrypt

The encrypt method takes plain text and outputs encrypted text. This encrypted text can be stored like any other text such as saving it in a TinyDB.

![](/assets/component_method_encrypt.png?raw=true)

### Decrypt

Decrypt method takes previously encrypted text and outputs the original unencrypted text.

![](/assets/component_method_decrypt.png?raw=true)

## Additional Information

This extension uses an encryption key that is stored on the device and is tied to the app. If the user uninstalls the app or clears the app storage, the key will also be deleted along with all the local user data. The first time the encryption method is invoked, the encryption key is generated. As the key is tied to the app and cannot be extracted, it provides a high level of security.

## FAQ

What API levels are supported?
> **API 23+** (Android 6)

Is there a size limit of the text that can be encrypted?
> **No**. This extension uses a symmetric encryption key (same key to encrypt and decrypt) which works well on larger amounts of data.

What is the encryption Cipher?
> **AES/GCM/NoPadding**

Can this extension be use to encrypt text before saving it online?
> **Yes**, but it may depend on the use case. Since only the device that encrypted the text can decrypt the text it may not meet design requirements. If the user uninstalls the app or clears the storage, the key will also be destroyed and there is no way left to decrypt the text.

Can this extension be used to encrypt user passwords or tokens?
> **Yes**. This is an example of the type of text (data) this app can safely encrypt before storing it locally on the device. The encrypted text will need to be stored as part of your app design such as saving it in a TinyDB.

Can this extension be used to secure a developer API key?
> **No**. This extension is for securely storing user data only.

Can this extension be used to share encrypted text between users or devices?
> **Indirectly**. Only the device which encrypted the text can decrypt the text. However, text can be encrypted using other encryption methods and shared. The encryption keys or passwords used can subsequently be encrypted using this extension and stored on the user device. To encrypt an encryption key, the key will have to be in text format such as base64 encoded.

Can this extension be used to share encrypted data between apps on user device?
> **No**. The encryption key can only be accessed by the app that creates the encryption key. (See previous question for options.)

Can this extension encrypt a dictionary?
> **Yes**. Ideally, you should be just encrypting sensitive values within the dictionary. However, if your dictionary consists of mostly sensitive data, you can encrypt a whole dictionary. When decrypting the dictionary data, the output will be text which is in JSON format. The output will then have to be converted from JSON into dictionary format. This can be accomplished using the *Web* component's *JSON Text Decode* method or other similar method.

Can you provide an example of how to encrypt and decrypt a dictionary?
> **Sure.**
>
> #### Encrypt dictionary:
> ![](/assets/dictionary_encrypt.png?raw=true)
> (Dictionary is converted to encrypted text.)
>
> #### Decrypt dictionary:
> ![](/assets/dictionary_decrypt.png?raw=true)
>
> However, it is probably better in most cases to just encrypt sensitive data.
>
> #### Encrypt value:
> ![](/assets/value_encrypt.png?raw=true)
>
> #### Decrypt value:
> ![](/assets/value_decrypt.png?raw=true)

## License
MIT License
