# Simple password manager for C# scripts

In scripts, it's common to use passwords, API keys, and other sensitive credentials. To safeguard them from theft or leaks (via script sharing, GitHub, etc), you can use this password manager.

This code gets a password. Here `"test"` is not a password; it's a password's name. The password is saved in a file (encrypted).
```csharp
/*/ c Passwords.cs; /*/

string pw = Passwords.Get("test");
print.it(pw);
```

The first time it shows a password input dialog and saves the password (encrypted). Also shows a key input dialog if a key for this computer/user still not saved.
To avoid password/key input dialogs at an inconvenient time, you can at first save passwords at a convenient time:
- Use the password manager dialog: run the password manager source file (`Passwords.cs`) or call **Passwords.ShowManagerUI**.
- Or call **Passwords.Get** or **Passwords.Save**.

## Setup
To use in [LibreAutomate](https://www.libreautomate.com), import file `Passwords.cs`.

To use elsewhere, add file `Passwords.cs` to your C# project. Also add NuGet package  [LibreAutomate](https://www.nuget.org/packages/LibreAutomate).

Also you may want to edit some values in the settings region. Recommended: change the *_entropy* value (make it unique).

## More info
Read **Passwords** class documentation comments.
