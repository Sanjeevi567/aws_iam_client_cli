mod credentials;
use credentials::{load_credential_from_env, CredentInitialize};
mod iam_ops;
use colored::Colorize;
use dotenv::dotenv;
use iam_ops::IamOps;
use inquire::{
    ui::{Attributes, RenderConfig, StyleSheet, Styled},
    Confirm, Password, Select, Text,
};
use std::{
    env::var,
    fs::File,
    fs::OpenOptions,
    io::{Read, Write},
};
#[tokio::main]
async fn main() {
    inquire::set_global_render_config(global_render_config());
    let mut credentials = CredentInitialize::default();
    let mut iam_ops = IamOps::build(credentials.build());
    let iam_operations = vec![
        "Verify Credentials\n",
        "User Operations in IAM\n",
        "User Group Operations in IAM\n",
        "Get Caller Identity\n",
        "Get Account Authorization Details\n",
        "Generate Credential Report\n",
        "Get Credential Report\n",
        "Get Account Summary\n",
        "Information about the Application\n",
        "Close the application\n",
    ];
    'main: loop {
        let choices = Select::new(
            "Identity and Access Management (IAM) operations on AWS\n",
            iam_operations.clone(),
        )
        .with_starting_cursor(0)
        .with_formatter(&|input| format!("The chosen operation is: '{input}'"))
        .with_page_size(6)
        .with_help_message("Click here https://tinyurl.com/2dv477cn to learn more")
        .prompt()
        .unwrap();
        match choices {
            "Verify Credentials\n" => {
                let confirm = Confirm::new("Load the credentials from the 'credentials' file or load them from the '.env' file, which should exist in the current or parent directory where you are running this\n")
                    .with_placeholder(
                        "Please enter 'Yes' to load from 'credential' or 'No' to load from '.env'.\n",
                    )
                    .with_help_message("Without proper credentials, no operations can be executed successfully")
                    .with_formatter(&|input| format!("Received Answer is: '{input}'"))
                    .prompt()
                    .unwrap();
                match confirm {
                    true => {
                        let cred_info = load_credential_from_env().await;
                        credentials.update(
                            cred_info.0.access_key_id(),
                            cred_info.0.secret_access_key(),
                            cred_info.1.as_deref(),
                        );
                        let config = credentials.build();
                        iam_ops = IamOps::build(config);
                    }
                    false => {
                        dotenv().ok();
                        let access_key = var("aws_access_key_id")
                        .expect("Ensure that the 'aws_access_key_id' environment variable is set, and its value is provided by AWS\n");
                        let secret_key = var("aws_secret_access_key")
                        .expect("Ensure that the 'aws_secret_access_key' environment variable is set, and its value is provided by AWS\n");
                        let region = var("region")
                        .expect("Ensure that the 'region' environment variable is set, and its value is provided by AWS\n");
                        credentials.update(&access_key, &secret_key, Some(&region));
                        let config = credentials.build();
                        iam_ops = IamOps::build(config);
                    }
                }
            }
            "User Operations in IAM\n" => {
                let user_ops = vec![
                    "Create User\n",
                    "Create Access Key\n",
                    "Create Login Profile\n",
                    "Delete Login Profile\n",
                    "Change Password\n",
                    "Update Access Key\n",
                    "Put User Policy\n",
                    "Attach User Policy\n",
                    "Get User\n",
                    "Retrieve IAM Users\n",
                    "List Users\n",
                    "List User Policies\n",
                    "List Attached User Policies\n",
                    "Delete Access key\n",
                    "Obtain the Policy Name and ARN for an IAM User\n",
                    "Delete User Policy\n",
                    "Detach User Policy\n",
                    "Go To Main Menu\n",
                ];
                loop {
                    let choices = Select::new("Operations in IAM User\n", user_ops.clone())
                        .with_page_size(5)
                        .with_formatter(&|input| format!("The chosen operation is: '{input}'"))
                        .with_starting_cursor(0)
                        .prompt()
                        .unwrap();
                    match choices {
                        "Create User\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Your account already contains these Users:\n {:#?}\n",
                                get_available_iam_users
                            );
                            let user_name = Text::new("The name of the user to create\n")
                                .with_placeholder(&placeholder_info)
                                .with_help_message("IAM user, group, role, and policy names must be unique within the account")
                                .with_formatter(&|input| format!("Received IAM User: '{input}'\n"))
                                .prompt()
                                .unwrap();
                            let path_prefix = Text::new("The path for the user name\n")
                                .with_placeholder("This parameter is optional. If it is not included, it defaults to a slash (/)\n")
                                .with_help_message("Press Enter if you prefer the default path")
                                .with_formatter(&|input| format!("Received Path Prefix Is: '{input}'\n"))
                                .prompt_skippable()
                                .unwrap()
                                .unwrap();
                            match user_name.is_empty() {
                                false => match path_prefix.is_empty() {
                                    false => {
                                        iam_ops.create_user(&user_name, Some(path_prefix)).await
                                    }
                                    true => iam_ops.create_user(&user_name, None).await,
                                },
                                true => println!(
                                    "{}\n",
                                    "Username cannot be left empty".bright_red().bold()
                                ),
                            }
                        }
                        "Retrieve IAM Users\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            println!(
                                "{}\n",
                                "IAM Users in the Provided Credentials".green().bold()
                            );
                            get_available_iam_users.into_iter().for_each(|user| {
                                println!("{}", user.green().bold());
                            });
                            println!("");
                            println!("{}\n","This information is used in various IAM operations as a placeholder for you to choose".yellow().bold());
                        }
                        "Obtain the Policy Name and ARN for an IAM User\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder = format!(
                                "IAM Users in the Provided Credentials\n: {:#?}",
                                get_available_iam_users
                            );
                            let iam_user_name = Text::new("Select the IAM user to obtain the Inline policy name and Managed policy ARN\n")
                                .with_formatter(&|input| format!("Received IAM User Name Is: '{input}'\n"))
                                .with_placeholder(&placeholder)
                                .prompt()
                                .unwrap();
                            match iam_user_name.is_empty() {
                                false => {
                                    let (get_available_policy_names, get_available_policy_arns) =
                                        iam_ops
                                            .get_policy_name_and_policy_arn_given_iam_user(
                                                &iam_user_name,
                                                None,
                                            )
                                            .await;
                                    println!("{}\n", "Inline User Policy Names".green().bold());
                                    get_available_policy_names.into_iter().for_each(
                                        |policy_name| {
                                            println!("{}", policy_name.green().bold());
                                        },
                                    );
                                    println!("");
                                    println!("{}\n", "Managed User Policy ARNs".green().bold());
                                    get_available_policy_arns
                                        .into_iter()
                                        .for_each(|policy_arn| {
                                            println!("{}", policy_arn.green().bold());
                                        });
                                    println!("");
                                    println!("{}\n","The policy names are used as placeholders in the 'Delete User Policy' option".yellow().bold());
                                    println!("{}\n","The policy ARNs are used as placeholders in the 'Detach User Policy' option".yellow().bold());
                                }
                                true => println!(
                                    "{}\n",
                                    "The User Name Can't be empty".bright_red().bold()
                                ),
                            }
                        }
                        "Create Access Key\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placholder_info = format!(
                                "Available IAM Users In your Account: {:#?}\n",
                                get_available_iam_users
                            );
                            let iam_user_name = Text::new(
                                "The name of the IAM user that the new key will belong to\n",
                            )
                            .with_placeholder(&placholder_info)
                            .with_formatter(&|input| {
                                format!("Received IAM User Name Is: '{input}'\n")
                            })
                            .prompt()
                            .unwrap();
                            match iam_user_name.is_empty() {
                                false => iam_ops.create_access_key(&iam_user_name).await,
                                true => println!(
                                    "{}\n",
                                    "IAM User Name cannot be left empty".bright_red().bold()
                                ),
                            }
                        }
                        "Create Login Profile\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Available IAM Users In your Account: {:#?}\n",
                                get_available_iam_users
                            );
                            let iam_user_name = Text::new("The name of the IAM user to create a password for. The user must already exist\n")
                                .with_placeholder(&placeholder_info)
                                .with_formatter(&|input| format!("Received IAM User Is: '{input}'\n"))
                                .prompt()
                                .unwrap();
                            let password = Password::new("The new password for the user\n")
                                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                                .without_confirmation()
                                .prompt()
                                .unwrap();
                            let password_reset_required = Confirm::new("Specifies whether the user is required to set a new password on next sign-in\n")
                                .with_placeholder("'Yes' is required for the user to set a new password on their next sign-in, while 'No' is used to apply the password you've created\n")
                                .with_formatter(&|input| format!("Received Answer Is: {input}\n"))
                                .with_help_message("If a password reset is required, you must grant the 'iam:ChangePassword' permission to the user\n")
                                .prompt()
                                .unwrap();
                            match (iam_user_name.is_empty(), password.is_empty()) {
                                (false, false) => {
                                    iam_ops
                                        .create_login_profile(
                                            &iam_user_name,
                                            &password,
                                            password_reset_required,
                                        )
                                        .await
                                }
                                _ => println!(
                                    "{}\n",
                                    "Iam User Name and the password cannot be empty"
                                        .bright_red()
                                        .bold()
                                ),
                            }
                        }
                        "Delete Login Profile\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Available IAM Users In your Account: {:#?}\n",
                                get_available_iam_users
                            );
                            let iam_user_name = Text::new(
                                "The name of the user whose password you want to delete\n",
                            )
                            .with_placeholder(&placeholder_info)
                            .with_formatter(&|input| format!("Received IAM User: '{input}'\n"))
                            .with_help_message("To prevent all user access, you must also either make any access keys inactive or delete them\n")
                            .prompt()
                            .unwrap();
                            match iam_user_name.is_empty() {
                                false => iam_ops.delete_login_profile(&iam_user_name).await,
                                true => println!(
                                    "{}\n",
                                    "IAM User Name cannot be Empty".bright_red().bold()
                                ),
                            }
                        }
                        "Change Password\n" => {
                            let confirm_visibility = Confirm::new("Choosing the visibility of the password while you're typing\n")
                                .with_placeholder("Type 'Yes' to display the password as you type it, or 'No' to mask it\n")
                                .with_formatter(&|input| format!("Received Answer Is: {input}\n"))
                                .prompt()
                                .unwrap();
                            let (old_password, new_password) = match confirm_visibility {
                                true => {
                                    let old_password = Password::new("Please enter the current password\n")
                                    .with_display_mode(inquire::PasswordDisplayMode::Full)
                                    .with_help_message("Please note that this option only works for IAM users, not for Root Users\n")
                                    .without_confirmation()
                                    .prompt()
                                    .unwrap();
                                    let new_password = Password::new(
                                        " Now, enter the new password to replace the old one\n",
                                    )
                                    .with_display_mode(inquire::PasswordDisplayMode::Full)
                                    .with_custom_confirmation_error_message(
                                        "The passwords should match\n",
                                    )
                                    .prompt()
                                    .unwrap();
                                    (old_password, new_password)
                                }
                                false => {
                                    let old_password = Password::new("Please enter the current password\n")
                                    .with_display_mode(inquire::PasswordDisplayMode::Masked)
                                    .with_help_message("Please note that this option only works for IAM users, not for Root Users\n")
                                    .without_confirmation()
                                    .prompt()
                                    .unwrap();
                                    let new_password = Password::new(
                                        " Now, enter the new password to replace the old one\n",
                                    )
                                    .with_display_mode(inquire::PasswordDisplayMode::Masked)
                                    .with_custom_confirmation_error_message(
                                        "The passwords should match\n",
                                    )
                                    .prompt()
                                    .unwrap();
                                    (old_password, new_password)
                                }
                            };
                            match (old_password.is_empty(), new_password.is_empty()) {
                                (false, false) => {
                                    let store_password = Confirm::new("Would you like to store the password?\n")
                                        .with_placeholder("Type 'Yes' to store it in the current directory, or 'No' to not store it\n")
                                        .with_formatter(&|input| format!("Received Answer Is: {input}\n"))
                                        .prompt()
                                        .unwrap();
                                    match store_password {
                                        true => {
                                            iam_ops
                                                .change_iam_user_password(
                                                    &old_password,
                                                    &new_password,
                                                )
                                                .await;
                                            let mut file = OpenOptions::new()
                                                .create(true)
                                                .read(true)
                                                .write(true)
                                                .open("iam_user_password.txt")
                                                .expect("Error while creating file\n");
                                            let buf = format!("The Password is: {new_password}\n");
                                            file.write_all(buf.as_bytes())
                                                .expect("Error While writing password");
                                        }
                                        false => {
                                            iam_ops
                                                .change_iam_user_password(
                                                    &old_password,
                                                    &new_password,
                                                )
                                                .await;
                                            println!(
                                                "{}\n",
                                                "No passwords have been saved".yellow().bold()
                                            );
                                        }
                                    }
                                }
                                _ => println!(
                                    "{}\n",
                                    "Passwords cannot be left empty".bright_red().bold()
                                ),
                            }
                        }
                        "Update Access Key\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Available IAM Users In your Account: {:#?}",
                                get_available_iam_users
                            );
                            let iam_user_name =
                                Text::new("The name of the user whose key you want to update.\n")
                                    .with_placeholder(&placeholder_info)
                                    .with_formatter(&|input| {
                                        format!("Received IAM User: '{input}'\n")
                                    })
                                    .prompt()
                                    .unwrap();
                            let access_key = Text::new("To update the status of the associated Secret Key, please enter the Access Key ID for the selected IAM user\n")
                                .with_placeholder("The access key is generated either when executing the 'Create Access Key' option or within the AWS console\n")
                                .with_formatter(&|input| format!("Received Access Key Is: '{input}'\n"))
                                .prompt()
                                .unwrap();
                            let valid_status = "Valid Values\n   Active | Inactive ";
                            let status_to_update = Text::new(
                                "The status you want to assign to the secret access key\n",
                            )
                            .with_placeholder(valid_status)
                            .with_formatter(&|input| format!("Received Status Is: '{input}'\n"))
                            .prompt()
                            .unwrap();
                            match (
                                iam_user_name.is_empty(),
                                access_key.is_empty(),
                                status_to_update.is_empty(),
                            ) {
                                (false, false, false) => {
                                    iam_ops
                                        .update_access_key_status(
                                            &iam_user_name,
                                            &access_key,
                                            &status_to_update,
                                        )
                                        .await;
                                }
                                _ => println!(
                                    "{}\n",
                                    "No Fields can't be left Empty".bright_red().bold()
                                ),
                            }
                        }
                        "Put User Policy\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Available IAM Users In your Account: {:#?}\n",
                                get_available_iam_users
                            );
                            let iam_user_name = Text::new(
                                "The name of the user to associate the policy with\n",
                            )
                            .with_placeholder(&placeholder_info)
                            .with_formatter(&|input| format!("Received IAM User: '{input}'\n"))
                            .with_help_message("Adds or updates an inline policy document that is embedded in the specified IAM user\n")
                            .prompt()
                            .unwrap();
                            let policy_name = Text::new("The name of the policy document\n")
                                .with_placeholder("a string of characters consisting of upper and lowercase alphanumeric characters with no spaces\n")
                                .with_formatter(&|input| format!("Received Policy Name Is: '{input}'\n"))
                                .prompt()
                                .unwrap();
                            let policy_document_path = Text::new("The policy document\n")
                                .with_placeholder("You can provide the path to the policy document in JSON format\n")
                                .with_formatter(&|input| format!("Received Policy Document path is: '{input}'\n"))
                                .with_help_message("For more information, please click here: https://tinyurl.com/2p5wp3ek\n")
                                .prompt()
                                .unwrap();
                            match (
                                iam_user_name.is_empty(),
                                policy_name.is_empty(),
                                policy_document_path.is_empty(),
                            ) {
                                (false, false, false) => {
                                    let mut read_json = File::open(&policy_document_path)
                                        .expect("Error while opening the File You specified\n");
                                    let mut policy_document = String::new();
                                    read_json.read_to_string(&mut policy_document).unwrap();
                                    iam_ops
                                        .put_user_policy(
                                            &iam_user_name,
                                            &policy_name,
                                            &policy_document,
                                        )
                                        .await
                                }
                                _ => println!(
                                    "{}\n",
                                    "No Fields can't be left Empty".bright_red().bold()
                                ),
                            }
                        }
                        "Attach User Policy\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Available IAM Users In your Account: {:#?}\n",
                                get_available_iam_users
                            );
                            let iam_user_name = Text::new(
                                "The name of the IAM user to attach the policy to\n",
                            )
                            .with_placeholder(&placeholder_info)
                            .with_formatter(&|input| format!("Received IAM User: '{input}'\n"))
                            .with_help_message(
                                "Attaches the specified managed policy to the specified user\n",
                            )
                            .prompt()
                            .unwrap();
                            let policy_arn = Text::new("The Amazon Resource Name (ARN) of the IAM policy you want to attach\n")
                                .with_placeholder("Example: The ARN value 'arn:aws:iam::aws:policy/AmazonS3FullAccess' grants full access to S3 buckets for the user'\n")
                                .with_help_message("For more information about ARNs, see https://tinyurl.com/5n7yukn6")
                                .with_formatter(&|input| {
                                    format!("Received Policy Arn Is: '{input}'\n")
                                })
                                .prompt()
                                .unwrap();
                            match (iam_user_name.is_empty(), policy_arn.is_empty()) {
                                (false, false) => {
                                    iam_ops
                                        .attach_user_policy(&iam_user_name, &policy_arn)
                                        .await;
                                }
                                _ => println!(
                                    "{}\n",
                                    "IAM User Name and Policy Arn can't be empty"
                                        .bright_red()
                                        .bold()
                                ),
                            }
                        }
                        "Get User\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Available IAM Users In your Account: {:#?}\n",
                                get_available_iam_users
                            );
                            let iam_user_name =
                                Text::new("The name of the user to get information about\n")
                                    .with_placeholder(&placeholder_info)
                                    .with_formatter(&|input| {
                                        format!("Received IAM User: '{input}'\n")
                                    })
                                    .prompt()
                                    .unwrap();
                            match iam_user_name.is_empty() {
                                false => iam_ops.get_user(&iam_user_name).await,
                                true => println!(
                                    "{}\n",
                                    "IAM user Name cannot be empty".bright_red().bold()
                                ),
                            }
                        }
                        "List Users\n" => {
                            let path_prefix = Text::new("The path prefix for filtering the results\n")
                            .with_placeholder("This parameter is optional. If it is not included, it defaults to a slash (/), listing all user names\n")
                            .with_formatter(&|input| format!("Received Path Prefix Is: '{input}'\n"))
                            .prompt_skippable()
                            .unwrap().unwrap();
                            match path_prefix.is_empty() {
                                true => {
                                    iam_ops.list_users(None).await;
                                }
                                false => {
                                    iam_ops.list_users(Some(path_prefix)).await;
                                }
                            }
                        }
                        "List User Policies\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Available IAM Users In your Account: {:#?}\n",
                                get_available_iam_users
                            );
                            let iam_user_name =
                                Text::new("The name of the user to list policies for\n")
                                    .with_placeholder(&placeholder_info)
                                    .with_help_message("Lists the names of the inline policies embedded in the specified IAM user")
                                    .with_formatter(&|input| {
                                        format!("Received IAM User: '{input}'\n")
                                    })
                                    .prompt()
                                    .unwrap();
                            match iam_user_name.is_empty() {
                                false => {
                                    iam_ops.list_user_policies(&iam_user_name).await;
                                }
                                true => println!(
                                    "{}\n",
                                    "IAM User Name can't be empty".bright_red().bold()
                                ),
                            }
                        }
                        "List Attached User Policies\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Available IAM Users In your Account: {:#?}\n",
                                get_available_iam_users
                            );
                            let iam_user_name =Text::new("The name of the user to list policies for\n")
                                    .with_placeholder(&placeholder_info)
                                    .with_help_message("Lists the names of the inline policies embedded in the specified IAM user")
                                    .with_formatter(&|input| {
                                        format!("Received IAM User: '{input}'\n")
                                    })
                                    .prompt()
                                    .unwrap();
                            let path_prefix = Text::new("The path prefix for filtering the results\n")
                                .with_placeholder("This parameter is optional. If it is not included, it defaults to a slash (/), listing all user names\n")
                                .with_formatter(&|input| format!("Received Path Prefix Is: '{input}'\n"))
                                .prompt_skippable()
                                .unwrap().unwrap();
                            match iam_user_name.is_empty() {
                                false => match path_prefix.is_empty() {
                                    false => {
                                        iam_ops
                                            .list_attached_user_policies(
                                                &iam_user_name,
                                                Some(path_prefix),
                                            )
                                            .await;
                                    }
                                    true => {
                                        iam_ops
                                            .list_attached_user_policies(&iam_user_name, None)
                                            .await;
                                    }
                                },
                                true => println!(
                                    "{}\n",
                                    "IAM user name can't be empty".bright_red().bold()
                                ),
                            }
                        }
                        "Delete Access key\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Available IAM Users In your Account:\n {:#?}\n",
                                get_available_iam_users
                            );
                            let iam_user_name = Text::new(
                                "The name of the user whose access key pair you want to delete.\n",
                            )
                            .with_placeholder(&placeholder_info)
                            .with_formatter(&|input| format!("Received IAM User: '{input}'\n"))
                            .prompt()
                            .unwrap();
                            let access_key = Text::new("Please enter the Access Key ID for the selected IAM user in order to delete both the Access Key and Secret Key\n")
                                .with_placeholder("The access key is generated either when executing the 'Create Access Key' option or within the AWS console\n")
                                .with_formatter(&|input| format!("Received Access Key Is: '{input}'\n"))
                                .prompt()
                                .unwrap();
                            match (iam_user_name.is_empty(), access_key.is_empty()) {
                                (false, false) => {
                                    iam_ops.delete_access_key(&iam_user_name, &access_key).await;
                                }
                                _ => println!(
                                    "{}\n",
                                    "None of the fields can be left empty".bright_red().bold()
                                ),
                            }
                        }
                        "Delete User Policy\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Available IAM Users In your Account:\n {:#?}\n",
                                get_available_iam_users
                            );
                            let iam_user_name = Text::new(
                                "Enter the IAM User name identifying the user that the policy is embedded in\n",
                            )
                            .with_placeholder(&placeholder_info)
                            .with_formatter(&|input| format!("Received IAM User: '{input}'\n"))
                            .prompt()
                            .unwrap();
                            match iam_user_name.is_empty() {
                                false => {
                                    let (get_available_policy_names, _) = iam_ops
                                        .get_policy_name_and_policy_arn_given_iam_user(
                                            &iam_user_name,
                                            None,
                                        )
                                        .await;
                                    let policy_names = format!("The policy names for the specified IAM user,{iam_user_name},are as follows:\n {:#?}",get_available_policy_names);
                                    let policy_name = Text::new("The name identifying the policy document to delete\n")
                                        .with_placeholder(&policy_names)
                                        .with_formatter(&|input| format!("Received Policy Name To Delete: '{input}'\n"))
                                        .with_help_message("To identify the policy name in your IAM Account, please review the placeholder information")
                                        .prompt()
                                        .unwrap();
                                    match policy_name.is_empty() {
                                        false => {
                                            iam_ops
                                                .delete_user_policy(&iam_user_name, &policy_name)
                                                .await;
                                        }
                                        true => println!(
                                            "{}\n",
                                            "Policy Name can't be empty".bright_red().bold()
                                        ),
                                    }
                                }
                                true => println!(
                                    "{}\n",
                                    "IAM User Name can't be empty".bright_red().bold()
                                ),
                            }
                        }
                        "Detach User Policy\n" => {
                            let get_available_iam_users = iam_ops.get_iam_users().await;
                            let placeholder_info = format!(
                                "Available IAM Users In your Account:\n {:#?}\n",
                                get_available_iam_users
                            );
                            let iam_user_name = Text::new(
                                "Enter the IAM User name identifying the user that the policy is embedded in\n",
                            )
                            .with_placeholder(&placeholder_info)
                            .with_formatter(&|input| format!("Received IAM User: '{input}'\n"))
                            .prompt()
                            .unwrap();
                            match iam_user_name.is_empty() {
                                false => {
                                    let (_, get_available_policy_arns) = iam_ops
                                        .get_policy_name_and_policy_arn_given_iam_user(
                                            &iam_user_name,
                                            None,
                                        )
                                        .await;
                                    let policy_arns = format!("Available Policy Arns for the specified IAM user,{iam_user_name},as follows:\n {:#?}",get_available_policy_arns);
                                    let policy_arn = Text::new("The Amazon Resource Name (ARN) of the IAM policy you want to detach\n")
                                    .with_placeholder(&policy_arns)
                                    .with_formatter(&|input| format!("Received Policy ARN To Detach: {input}\n"))
                                    .prompt()
                                    .unwrap();
                                    match policy_arn.is_empty() {
                                        false => {
                                            iam_ops
                                                .detatch_user_policy(&iam_user_name, &policy_arn)
                                                .await;
                                        }
                                        true => println!(
                                            "{}\n",
                                            "The Policy Arn can't be empty".bright_red().bold()
                                        ),
                                    }
                                }
                                true => println!(
                                    "{}\n",
                                    "IAM User Name can't be empty".bright_red().bold()
                                ),
                            }
                        }
                        "Go To Main Menu\n" => continue 'main,
                        _ => println!("Never Reach"),
                    }
                }
            }
            "User Group Operations in IAM\n" => {
                let user_group_ops = vec![
                    "Create Group\n",
                    "Add User To Group\n",
                    "Get Group\n",
                    "Retrieve Group Names\n",
                    "List Groups\n",
                    "Put Group Policy\n",
                    "List Group Policies\n",
                    "Attach Group Policy\n",
                    "List Attached Group Policies\n",
                    "Get Users within a Group\n",
                    "Remove User From Group\n",
                    "Delete Group Policy\n",
                    "Retrieve the Policy Name and ARN for a Group\n",
                    "Detach Group Policy\n",
                    "Delete Group\n",
                    "Go To Main Menu\n",
                ];
                loop {
                    let choices =
                        Select::new("Operations in IAM User Group\n", user_group_ops.clone())
                            .with_page_size(5)
                            .with_formatter(&|input| format!("The chosen operation is: {input}"))
                            .with_starting_cursor(0)
                            .prompt()
                            .unwrap();
                    match choices {
                        "Create Group\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Your account already contains these groups:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name = Text::new("The name of the group to create. Do not include the path in this value\n")
                                .with_placeholder(&available_group_names)
                                .with_formatter(&|input| {
                                    format!("Received Group Name is: '{input}'\n")
                                })
                                .prompt()
                                .unwrap();
                            let path_prefix = Text::new("The path for the Group name\n")
                            .with_placeholder("This parameter is optional. If it is not included, it defaults to a slash (/)\n")
                            .with_help_message("Press Enter if you prefer the default path")
                            .with_formatter(&|input| format!("The Path Prefix is: '{input}'\n"))
                            .prompt_skippable()
                            .unwrap()
                            .unwrap();
                            match group_name.is_empty() {
                                false => match path_prefix.is_empty() {
                                    false => {
                                        iam_ops.create_group(&group_name, Some(path_prefix)).await;
                                    }
                                    true => {
                                        iam_ops.create_group(&group_name, None).await;
                                    }
                                },
                                true => println!(
                                    "{}\n",
                                    "The Group Name can't be Empty".bright_red().bold()
                                ),
                            }
                        }
                        "Retrieve Group Names\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            println!(
                                "{}\n",
                                "Available Group Names in the provided credentials:"
                                    .green()
                                    .bold()
                            );
                            get_available_group_names
                                .into_iter()
                                .for_each(|group_name| {
                                    println!("{}", group_name.green().bold());
                                });
                            println!("{}\n","These group names serve as placeholders in various IAM group operations".yellow().bold());
                        }
                        "Get Users within a Group\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Available Group Names In Your Account:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name =
                                Text::new("Enter a group name to add an IAM user to\n")
                                    .with_placeholder(&available_group_names)
                                    .with_formatter(&|input| {
                                        format!("Received Group Name Is: '{input}'\n")
                                    })
                                    .prompt()
                                    .unwrap();
                            match group_name.is_empty() {
                                false => {
                                    let get_available_iam_users_in_a_group =
                                        iam_ops.get_iam_users_in_a_group(&group_name).await;
                                    println!(
                                        "Available Users In the {} Group",
                                        group_name.green().bold()
                                    );
                                    get_available_iam_users_in_a_group.into_iter().for_each(
                                        |user| {
                                            println!("{}", user.green().bold());
                                        },
                                    );
                                    println!("");
                                    println!("{}\n","The information is used as a placeholder in the 'Remove User From Group' option".yellow().bold());
                                }
                                true => println!(
                                    "{}\n",
                                    "Group Name can't be empty".bright_red().bold()
                                ),
                            }
                        }
                        "Retrieve the Policy Name and ARN for a Group\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Available Group Names In Your Account:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name =
                                Text::new("Enter a group name to add an IAM user to\n")
                                    .with_placeholder(&available_group_names)
                                    .with_formatter(&|input| {
                                        format!("Received Group Name Is: '{input}'\n")
                                    })
                                    .prompt()
                                    .unwrap();
                            match group_name.is_empty() {
                                false => {
                                    let (
                                        get_available_group_policy_names,
                                        get_available_group_policy_arns,
                                    ) = iam_ops
                                        .get_group_inline_policy_name_and_attached_policy_arn(
                                            &group_name,
                                        )
                                        .await;
                                    println!(
                                        "{}\n",
                                        "Available Inline Group Policies (Names Only)"
                                            .green()
                                            .bold()
                                    );
                                    get_available_group_policy_names.into_iter().for_each(
                                        |policy_name| {
                                            println!("{}", policy_name.green().bold());
                                        },
                                    );
                                    println!("");
                                    get_available_group_policy_arns.into_iter().for_each(
                                        |policy_arn| {
                                            println!("{}", policy_arn.green().bold());
                                        },
                                    );
                                    println!("");
                                    println!("{}\n","Both of these pieces of information are used as placeholders in the 'Delete Group Policy' and 'Detach Group Policy' options.".yellow().bold());
                                }
                                true => println!(
                                    "{}\n",
                                    "Group Name can't be empty".bright_red().bold()
                                ),
                            }
                        }
                        "Add User To Group\n" => {
                            let (get_available_group_names, get_available_iam_users) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Available Group Names In Your Account:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name =
                                Text::new("Enter a group name to add an IAM user to\n")
                                    .with_placeholder(&available_group_names)
                                    .with_formatter(&|input| {
                                        format!("Received Group Name Is: '{input}'\n")
                                    })
                                    .prompt()
                                    .unwrap();
                            let avaialble_iam_users = format!(
                                "Available IAM Users in Your Account:\n {:#?}",
                                get_available_iam_users
                            );
                            let iam_user_name = Text::new(
                                "Please enter the IAM username to add it to the specified group\n",
                            )
                            .with_formatter(&|input| {
                                format!("Received IAM User Name Is: '{input}'\n")
                            })
                            .with_placeholder(&avaialble_iam_users)
                            .prompt()
                            .unwrap();
                            match (group_name.is_empty(), iam_user_name.is_empty()) {
                                (false, false) => {
                                    iam_ops.add_user_to_group(&group_name, &iam_user_name).await;
                                }
                                _ => println!("{}\n", "Fields can't be empty".bright_red().bold()),
                            }
                        }
                        "Get Group\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Available Group Names In Your Account:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name =
                                Text::new("Provide the name of the group for which you would like to receive details\n")
                                    .with_placeholder(&available_group_names)
                                    .with_formatter(&|input| {
                                        format!("Received Group Name Is: '{input}'\n")
                                    })
                                    .prompt()
                                    .unwrap();
                            match group_name.is_empty() {
                                false => {
                                    iam_ops.get_group(&group_name).await;
                                }
                                true => println!(
                                    "{}\n",
                                    "Group Name can't be Empty".bright_red().bold()
                                ),
                            }
                        }
                        "List Groups\n" => {
                            let path_prefix = Text::new("The path prefix for filtering the results\n")
                            .with_placeholder("This parameter is optional. If it is not included, it defaults to a slash (/),listing all groups\n")
                            .with_help_message("Press Enter if you prefer the default path")
                            .with_formatter(&|input| format!("Received Path Prefix is: '{input}'\n"))
                            .prompt_skippable()
                            .unwrap()
                            .unwrap();
                            match path_prefix.is_empty() {
                                false => {
                                    iam_ops.list_groups(Some(path_prefix)).await;
                                }
                                true => {
                                    iam_ops.list_groups(None).await;
                                }
                            }
                        }
                        "Put Group Policy\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Available Group Names In Your Account:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name = Text::new(
                                "Enter the name of the group to associate the policy with\n",
                            )
                            .with_placeholder(&available_group_names)
                            .with_formatter(&|input| format!("Received Group Name Is: '{input}'\n"))
                            .prompt()
                            .unwrap();
                            let policy_name = Text::new("Provide a friendly name for the policy document\n")
                                .with_formatter(&|input| {
                                    format!("Received Policy Name To Update: '{input}'\n")
                                })
                                .with_placeholder("This policy name will serve as the identifier for associating it with the actual policy document\n")
                                .prompt()
                                .unwrap();
                            let policy_document_path = Text::new("The policy document\n")
                                .with_placeholder("You can provide the path to the policy document in JSON format\n")
                                .with_formatter(&|input| format!("Received Policy Document path is: '{input}'\n"))
                                .with_help_message("For more information, please click here: https://tinyurl.com/2p5wp3ek\n")
                                .prompt()
                                .unwrap();
                            match (
                                group_name.is_empty(),
                                policy_name.is_empty(),
                                policy_document_path.is_empty(),
                            ) {
                                (false, false, false) => {
                                    let mut read_json = File::open(&policy_document_path)
                                        .expect("Error while opening the File You specified\n");
                                    let mut policy_document = String::new();
                                    read_json.read_to_string(&mut policy_document).unwrap();
                                    iam_ops
                                        .put_group_policy(
                                            &group_name,
                                            &policy_name,
                                            &policy_document,
                                        )
                                        .await;
                                }
                                _ => println!(
                                    "{}\n",
                                    "Fields can't be left empty".bright_red().bold()
                                ),
                            }
                        }
                        "List Group Policies\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Available Group Names In Your Account:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name = Text::new(
                                "The name of the group to list policies for\n",
                            )
                            .with_placeholder(&available_group_names)
                            .with_help_message("Lists the names of the inline policies that are embedded in the specified IAM group")
                            .with_formatter(&|input| format!("Received Group Name Is: '{input}'\n"))
                            .prompt()
                            .unwrap();
                            match group_name.is_empty() {
                                false => {
                                    iam_ops.list_group_policies(&group_name).await;
                                }
                                true => println!(
                                    "{}\n",
                                    "Group Name Can't be Empty".bright_red().bold()
                                ),
                            }
                        }
                        "Attach Group Policy\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Available Group Names In Your Account:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name = Text::new(
                                "The name of the group to attach the policy to\n",
                            )
                            .with_placeholder(&available_group_names)
                            .with_help_message(
                                "Attaches the specified managed policy to the specified IAM group",
                            )
                            .with_formatter(&|input| format!("Received Group Name Is: '{input}'\n"))
                            .prompt()
                            .unwrap();
                            let policy_arn = Text::new("The Amazon Resource Name (ARN) of the IAM policy you want to attach\n")
                                .with_placeholder("Example: The ARN value 'arn:aws:iam::aws:policy/AmazonSESFullAccess' grants full access to Simple Email Service(SES) for the Specified Group'\n")
                                .with_help_message("For more information about ARNs, see https://tinyurl.com/5n7yukn6")
                                .with_formatter(&|input| {
                                    format!("Received Policy Arn Is: '{input}'\n")
                                })
                                .prompt()
                                .unwrap();
                            match (group_name.is_empty(), policy_arn.is_empty()) {
                                (false, false) => {
                                    iam_ops.attach_group_policy(&group_name, &policy_arn).await;
                                }
                                _ => println!(
                                    "{}\n",
                                    "Group Name and Managed Policy Arn can't be empty"
                                        .bright_red()
                                        .bold()
                                ),
                            }
                        }
                        "List Attached Group Policies\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Available Group Names In Your Account:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name = Text::new(
                            "The name of the group to list attached policies for\n",
                        )
                        .with_placeholder(&available_group_names)
                        .with_help_message("Lists all managed policies that are attached to the specified IAM group")
                        .with_formatter(&|input| format!("Received Group Name Is: '{input}'\n"))
                        .prompt()
                        .unwrap();
                            let path_prefix = Text::new("The path prefix for filtering the results\n")
                    .with_placeholder("This parameter is optional. If it is not included, it defaults to a slash (/),listing all attached Group Policies\n")
                    .with_help_message("Press Enter if you prefer the default path")
                    .with_formatter(&|input| format!("The Path Prefix is: '{input}'\n"))
                    .prompt_skippable()
                    .unwrap()
                    .unwrap();
                            match group_name.is_empty() {
                                false => match path_prefix.is_empty() {
                                    false => {
                                        iam_ops
                                            .list_attached_group_policies(
                                                &group_name,
                                                Some(path_prefix),
                                            )
                                            .await;
                                    }
                                    true => {
                                        iam_ops
                                            .list_attached_group_policies(&group_name, None)
                                            .await;
                                    }
                                },
                                true => println!(
                                    "{}\n",
                                    "Group Name can't be empty".bright_red().bold()
                                ),
                            }
                        }
                        "Remove User From Group\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Available Group Names In Your Account:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name =
                                Text::new("Provide the group name from which you would like to remove a user\n")
                                    .with_placeholder(&available_group_names)
                                    .with_formatter(&|input| {
                                        format!("Received Group Name Is: '{input}'\n")
                                    })
                                    .prompt()
                                    .unwrap();
                            let get_available_iam_users_in_a_group =
                                iam_ops.get_iam_users_in_a_group(&group_name).await;
                            let avaialble_iam_users = format!(
                                "Available IAM users in the specified group name:{group_name}\n {:#?}",
                                get_available_iam_users_in_a_group
                            );
                            let iam_user_name = Text::new(
                                "Specify the IAM user you wish to remove from the group\n",
                            )
                            .with_formatter(&|input| {
                                format!("Received IAM User Name Is: '{input}'\n")
                            })
                            .with_placeholder(&avaialble_iam_users)
                            .with_help_message("message")
                            .prompt()
                            .unwrap();
                            match (group_name.is_empty(), iam_user_name.is_empty()) {
                                (false, false) => {
                                    iam_ops
                                        .remove_user_from_group(&group_name, &iam_user_name)
                                        .await;
                                }
                                _ => println!("{}\n", "Fields can't be empty".bright_red().bold()),
                            }
                        }
                        "Delete Group Policy\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Available Group Names In Your Account:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name = Text::new(
                                "Provide the group name to delete the associated inline policy\n",
                            )
                            .with_placeholder(&available_group_names)
                            .with_formatter(&|input| format!("Received Group Name Is: '{input}'\n"))
                            .prompt()
                            .unwrap();
                            match group_name.is_empty() {
                                false => {
                                    let (get_available_group_policy_names, _) = iam_ops
                                        .get_group_inline_policy_name_and_attached_policy_arn(
                                            &group_name,
                                        )
                                        .await;
                                    let policy_names = format!(
                                    "Available Inline Policy Names for the specified Group: {group_name}\n {:#?}",
                                    get_available_group_policy_names
                                );
                                    let policy_name = Text::new("The name identifying the policy document to delete\n")
                                            .with_placeholder(&policy_names)
                                            .with_formatter(&|input| format!("Received Policy Name To Delete: '{input}'\n"))
                                            .with_help_message("The group's inline policy names associated with the group can be accessed by selecting 'List Group Policies'")
                                            .prompt()
                                            .unwrap();
                                    match policy_name.is_empty() {
                                        false => {
                                            iam_ops
                                                .delete_group_policy(&group_name, &policy_name)
                                                .await;
                                        }
                                        true => println!(
                                            "{}\n",
                                            "Inline Policy Name can't be Empty".bright_red().bold()
                                        ),
                                    }
                                }
                                true => println!(
                                    "{}\n",
                                    "Group Name can't be Empty".bright_red().bold()
                                ),
                            }
                        }
                        "Detach Group Policy\n" => {
                            let (get_available_group_names, _) =
                                iam_ops.get_group_names_and_iam_users().await;
                            let available_group_names = format!(
                                "Available Group Names In Your Account:\n {:#?}",
                                get_available_group_names
                            );
                            let group_name = Text::new(
                                "Provide the group name to detach the associated attached or managed policy\n",
                            )
                            .with_placeholder(&available_group_names)
                            .with_formatter(&|input| format!("Received Group Name Is: '{input}'\n"))
                            .prompt()
                            .unwrap();
                            match group_name.is_empty() {
                                false => {
                                    let (_, get_available_group_policy_arns) = iam_ops
                                        .get_group_inline_policy_name_and_attached_policy_arn(
                                            &group_name,
                                        )
                                        .await;
                                    let policy_arns = format!(
                                    "Available Managed Policy Arns for the specified Group: {group_name}\n {:#?}",
                                    get_available_group_policy_arns
                                );
                                    let policy_arn = Text::new("The name identifying the policy document to delete\n")
                                            .with_placeholder(&policy_arns)
                                            .with_formatter(&|input| format!("Received Policy Arn To Delete: '{input}'\n"))
                                            .with_help_message("To access the policy ARNs associated with a group that are either attached or managed, choose 'List Attached Group Policies")
                                            .prompt()
                                            .unwrap();
                                    match policy_arn.is_empty() {
                                        false => {
                                            iam_ops
                                                .detach_group_policy(&group_name, &policy_arn)
                                                .await;
                                        }
                                        true => println!(
                                            "{}\n",
                                            "Attached Or Managed Policy Arn can't be Empty"
                                                .bright_red()
                                                .bold()
                                        ),
                                    }
                                }
                                true => println!(
                                    "{}\n",
                                    "Group Name can't be Empty".bright_red().bold()
                                ),
                            }
                        }
                        "Delete Group\n" => {
                            let pre_caution = Confirm::new("The group does not have any IAM users or attached policies.\nExecute the 'Get Group' and 'List Attached Group Policies' options before proceeding with this action\n")
                                .with_placeholder("To continue deleting a group, type 'Yes' ,choose 'No' to execute those actions\n")
                                .prompt()
                                .unwrap();
                            match pre_caution {
                                true => {
                                    let (get_available_group_names, _) =
                                        iam_ops.get_group_names_and_iam_users().await;
                                    let available_group_names = format!(
                                        "Available Group Names In Your Account:\n {:#?}",
                                        get_available_group_names
                                    );
                                    let group_name = Text::new(
                                        "Please enter the group name you wish to delete\n",
                                    )
                                    .with_placeholder(&available_group_names)
                                    .with_formatter(&|input| {
                                        format!("Received Group Name To Delete: '{input}'\n")
                                    })
                                    .prompt()
                                    .unwrap();
                                    match group_name.is_empty() {
                                        false => {
                                            iam_ops.delete_group(&group_name).await;
                                        }
                                        true => println!(
                                            "{}\n",
                                            "Group Name can't be Empty".bright_red().bold()
                                        ),
                                    }
                                }
                                false => {
                                    println!(
                                        "{}\n",
                                        "Going back to the Options menu".bright_green().bold()
                                    )
                                }
                            }
                        }
                        "Go To Main Menu\n" => continue 'main,
                        _ => println!("Never Reach"),
                    }
                }
            }
            "Get Caller Identity\n" => {
                let _ignore_result = iam_ops.get_caller_identity(true).await;
            }
            "Get Account Authorization Details\n" => {
                iam_ops.get_account_autherization_details().await;
            }
            "Generate Credential Report\n" => {
                iam_ops.generate_credential_report().await;
            }
            "Get Credential Report\n" => {
                iam_ops.get_credential_report().await;
            }
            "Get Account Summary\n" => {
                iam_ops.get_account_summary().await;
            }
            "Information about the Application\n" => {
                println!("{}\n","1) An Easy-to-Use CLI Interface Application for Interacting with AWS IAM Service".bright_green().bold());
                println!("{}\n","2) If you find this description unclear, please click here https://tinyurl.com/35f44wzs to learn about supported IAM operations".bright_green().bold());
                println!("{}\n","3) This application is written in Rust and utilizes the Inquire crate to provide real-world software development experience".bright_green().bold());
                println!("{}\n","4) This application is not a scam or malware designed to steal your credentials. The complete source code is available here https://tinyurl.com/sjtt729f for you to verify its authenticity".bright_green().bold());
                println!("{}\n","5) If you appreciate this CLI tool or would like to discuss it further, please visit the comments section https://sanjuvi.github.io/Blog/posts/Aws-Iam/".bright_green().bold());
            }
            "Close the application\n" => break 'main,
            _ => println!("Never Reach"),
        }
    }
}
fn global_render_config() -> RenderConfig {
    RenderConfig::default()
        .with_prompt_prefix(Styled::new("🔑").with_fg(inquire::ui::Color::DarkBlue))
        .with_text_input(StyleSheet::new().with_fg(inquire::ui::Color::LightGreen))
        .with_highlighted_option_prefix(Styled::new("👉"))
        .with_help_message(StyleSheet::new().with_fg(inquire::ui::Color::DarkYellow))
        .with_answer(
            StyleSheet::new()
                .with_attr(Attributes::BOLD)
                .with_fg(inquire::ui::Color::DarkGreen),
        )
}
