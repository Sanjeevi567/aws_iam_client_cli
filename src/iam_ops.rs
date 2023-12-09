use std::{
    fs::{self, OpenOptions},
    io::Write,
};

use aws_config::SdkConfig;
use aws_sdk_iam::{
    operation::{
        get_account_summary::GetAccountSummaryOutput,
        get_credential_report::GetCredentialReportOutput,
    },
    primitives::DateTimeFormat,
    types::{
        AccessKey, AttachedPolicy, Group, GroupDetail, ManagedPolicyDetail, RoleDetail, User,
        UserDetail,
    },
    Client as IamClient,
};
use aws_sdk_sts::Client as StsClient;
use colored::Colorize;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, CellAlignment, Color, Table};
use std::fs::File;
use tokio_stream::StreamExt;
use urldecode::decode;
/// You must be root user to perform this operations
pub struct IamOps {
    config: SdkConfig,
}
impl IamOps {
    pub fn build(config: SdkConfig) -> Self {
        Self { config }
    }
    fn get_config(&self) -> &SdkConfig {
        &self.config
    }
    pub async fn create_role(
        &self,
        assume_policy_path: &str,
        description: Option<String>,
        path_prefix: Option<String>,
        max_session_in_hour: i32,
        role_name: &str,
    ) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let read_assume_policy_doc = fs::read_to_string(assume_policy_path)
            .expect("Error while opening Assume Role Policy file path\n");
        let max_session = if (max_session_in_hour > 12) | (max_session_in_hour < 1) {
            None
        } else {
            let convert_to_seconds = max_session_in_hour * (60 * 60);
            Some(convert_to_seconds)
        };
        let outputs = client
            .create_role()
            .role_name(role_name)
            .set_max_session_duration(max_session)
            .assume_role_policy_document(read_assume_policy_doc)
            .set_description(description)
            .set_path(path_prefix)
            .send()
            .await
            .expect("Error while creating Role\n");
        if let Some(role) = outputs.role {
            if let Some(role_id) = role.role_id {
                println!("Role ID: {}", role_id.green().bold());
            }
            if let Some(role_arn) = role.arn {
                println!("Role Arn: {}", role_arn.green().bold());
            }
            if let Some(date) = role.create_date {
                let convert = date.fmt(DateTimeFormat::HttpDate).ok();
                if let Some(time) = convert {
                    println!("Role Creation Date and Time: {}", time.green().bold());
                }
            }
            if let Some(max_session) = role.max_session_duration {
                println!(
                    "The maximum session duration (in hours) for the created role: {}",
                    (max_session / (60 * 60)).to_string().green().bold()
                );
            }
        }
    }
    pub async fn attach_role_policy(&self, role_name: &str, policy_arn: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .attach_role_policy()
            .policy_arn(policy_arn)
            .role_name(role_name)
            .send()
            .await
            .expect("Error while Attaching Role Policy\n");
        println!("The provided managed policy with the policy ARN '{}' has been successfully attached to the Role Name: '{}'\n",policy_arn.green().bold(),role_name.green().bold());
        println!(
            "{}\n",
            "To add or update an inline role policy, execute the 'Put Role Policy' option"
                .yellow()
                .bold()
        );
    }
    pub async fn put_role_policy(
        &self,
        role_name: &str,
        policy_name: &str,
        policy_document_path: &str,
    ) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let policy_document = fs::read_to_string(policy_document_path)
            .expect("Error while opening the Inline Policy Document Path you provided\n");
        client
            .put_role_policy()
            .role_name(role_name)
            .policy_name(policy_name)
            .policy_document(policy_document)
            .send()
            .await
            .expect("Error while Putting Role Policy\n");
        println!("The inline policy named {} with the specified policy document has been added or updated for the Role: {}\n",policy_name.green().bold(),role_name.green().bold());
        println!(
            "{}\n",
            "To attach a managed role policy, execute the 'Attach Role Policy' option"
                .yellow()
                .bold()
        );
    }
    pub async fn create_user(&self, iam_user_name: &str, path_prefix: Option<String>) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .create_user()
            .user_name(iam_user_name)
            .set_path(path_prefix)
            .send()
            .await
            .expect("Error while creating IAM user\n");
        println!("The IAM user with the username {} has been created successfully.\nTo obtain information about this user, please use the '{}' option\n",iam_user_name.green().bold(),"Get User".yellow().bold());
        println!(
            "To get info about an IAM user, select the '{}' option\n",
            "Get User".yellow().bold()
        );
    }
    pub async fn get_iam_users(&self) -> Vec<String> {
        let config = self.get_config();
        let client = IamClient::new(config);
        let streaming_output = client.list_users().into_paginator().items().send();
        let outputs = streaming_output
            .collect::<Result<Vec<User>, _>>()
            .await
            .expect("Error while Getting IAM user Names\n");
        let mut iam_user_names = Vec::new();
        outputs.into_iter().for_each(|user| {
            let iam_user = user.user_name;
            if let Some(user_name) = iam_user {
                iam_user_names.push(user_name);
            }
        });
        iam_user_names
    }
    pub async fn create_access_key(&self, iam_user_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let output = client
            .create_access_key()
            .user_name(iam_user_name)
            .send()
            .await
            .expect("Error while creating access key for IAM user\n");
        let mut user_table = Table::new();
        user_table
            .load_preset(UTF8_FULL)
            .set_width(80)
            .set_header(vec![Cell::new(
                "Access Key Information that you just created",
            )
            .fg(Color::Yellow)
            .add_attribute(Attribute::Bold)
            .set_alignment(CellAlignment::Left)]);
        if let Some(access_key) = output.access_key {
            let wrap = WrapAccessKey::wrap(access_key);
            let user_name = wrap.user_name();
            let access_key = wrap.access_key();
            let secret_key = wrap.secret_access_key();
            let create_time = wrap.create_date();
            let status = wrap.status();
            if let (Some(uname), Some(ackey), Some(seckey), Some(time), Some(status)) =
                (user_name, access_key, secret_key, create_time, status)
            {
                user_table.add_row(vec![
                    Cell::new(format!("IAM User Name: {}", uname))
                        .fg(Color::Green)
                        .add_attribute(Attribute::Bold)
                        .set_alignment(CellAlignment::Center),
                    Cell::new(format!("Access Key ID: {}", ackey))
                        .fg(Color::Green)
                        .add_attribute(Attribute::Bold)
                        .set_alignment(CellAlignment::Center),
                    Cell::new(format!("Creation Date and Time: {}", time))
                        .fg(Color::Green)
                        .add_attribute(Attribute::Bold)
                        .set_alignment(CellAlignment::Center),
                    Cell::new(format!("Status: {}", status))
                        .fg(Color::Green)
                        .add_attribute(Attribute::Bold)
                        .set_alignment(CellAlignment::Center),
                ]);
                //println!("IAM User Name: {}", uname.green().bold());
                //println!("Access Key ID: {}", ackey.green().bold());
                //println!("Creation Date and Time: {}", time.green().bold());
                //println!("Status: {}\n\n", status.green().bold());
                println!("{}", user_table);
                let path_name = format!("IAM_{iam_user_name}_Credentials");
                let mut file = OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .open(&path_name)
                    .expect("Error while creating file\n");
                let buf = format!("aws_access_key_id={ackey}\naws_secret_access_key={seckey}");
                println!("{}\n","The secret is only accessible the first time we create an access key and cannot be recovered. Instead, create the access key again".yellow().bold());
                match file.write_all(buf.as_bytes()) {
                    Ok(_) =>println!("The access key and secret key have been written to the current directory with the filename 'IAM_{}_Credentials'.Be sure to place them in an appropriate location",iam_user_name.bright_green().bold()),
                    Err(_) => println!("Error while writing credential info\n")
                }
            }
        }
        println!(
            "{}\n",
            "To delete an access key, select the 'Delete Access Key' option"
                .yellow()
                .bold()
        );
    }
    pub async fn get_caller_identity(&self, print_info: bool) -> Result<String, &'static str> {
        let config = self.get_config();
        let client = StsClient::new(config);
        let output = client.get_caller_identity().send().await;

        match output {
            Ok(output) => {
                let mut account_id_ = String::new();

                if print_info {
                    if let (Some(account_id), Some(arn), Some(uid)) =
                        (output.account, output.arn, output.user_id)
                    {
                        println!(
                        "The AWS account ID number of the account that owns or contains the calling entity: {}\nThe unique identifier of the calling entity: {}\nThe AWS ARN associated with the calling entity: {}",
                        account_id.green().bold(),
                        uid.green().bold(),
                        arn.green().bold()
                    );
                        println!("");
                    }
                } else {
                    if let Some(acc_id) = output.account {
                        account_id_.push_str(&acc_id);
                    }
                }
                Ok(account_id_)
            }
            Err(_) => {
                let error_msg = "Before proceeding with this, it's important to verify your credentials. Please execute the 'Verify Credentials' option first".red().bold();
                println!("{}\n", error_msg);
                Err("Error while getting Caller Identity\n")
            }
        }
    }
    pub async fn create_login_profile(
        &self,
        iam_user_name: &str,
        new_pass: &str,
        password_reset_required: bool,
    ) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .create_login_profile()
            .user_name(iam_user_name)
            .password(new_pass)
            .password_reset_required(password_reset_required)
            .send()
            .await
            .expect("Error while creating Login Profile\n");
        let path_name = format!("{iam_user_name}_login_profile.txt");
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path_name)
            .expect("Error while creating file\n");
        let account_id_ = self.get_caller_identity(false).await;
        match account_id_ {
            Ok(account_id) => {
                let sign_in_url = format!("https://{account_id}.signin.aws.amazon.com/console/");
                let buf = format!("Accound ID: {account_id}\nIAM User Name: {iam_user_name}\nIAM Password: {new_pass}\nPassword Reset Required: {password_reset_required}\nSignIn Url :{sign_in_url}\nConsole Url: console.aws.amazon.com/\n");
                file.write_all(buf.as_bytes())
                    .expect("Error while writing Login Profile\n");
                println!("All the information necessary to sign in as an IAM user has been written to the current directory in a file named {}\n","'specified_iam_user_name'_login_profile.txt'".green().bold());
                println!(
                    "{}\n",
                    "Please provide this file to anyone you want to grant access to"
                        .yellow()
                        .bold()
                );
                println!(
                    "{}\n",
                    "To change your password, please select the 'Change Password' option"
                        .yellow()
                        .bold()
                );
                println!(
                    "{}\n",
                    "To delete a LoginProfile, select the 'Delete Login Profile 'option"
                        .yellow()
                        .bold()
                );
            }
            Err(_) => println!(
                "{}\n",
                "Error while getting Caller Identity Make sure you verfied the credentials first"
                    .red()
                    .bold()
            ),
        }
    }
    pub async fn delete_login_profile(&self, iam_user_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .delete_login_profile()
            .user_name(iam_user_name)
            .send()
            .await
            .expect("Error while deleting Login Profile\n");
        println!(
            "The LogineProfile has been deleted for the IAM user {}\n",
            iam_user_name.green().bold()
        );
        println!(
            "{}\n",
            "To create a LoginProfile, select the 'Create Login Profile' option"
                .yellow()
                .bold()
        );
    }
    pub async fn change_iam_user_password(&self, old_pass: &str, new_pass: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .change_password()
            .old_password(old_pass)
            .new_password(new_pass)
            .send()
            .await
            .expect("Error while Changing password\n");
        println!(
            "{}\n",
            "The password has been successfully updated".green().bold()
        );
    }
    pub async fn update_access_key_status(
        &self,
        iam_user_name: &str,
        access_key: &str,
        status_to_update: &str,
    ) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let status_builder = aws_sdk_iam::types::StatusType::from(status_to_update);
        let status = status_builder.as_str().to_owned();
        client
            .update_access_key()
            .access_key_id(access_key)
            .user_name(iam_user_name)
            .status(status_builder)
            .send()
            .await
            .expect("Error while updating AccessKey status\n");
        println!(
            "The status has been updated to: {}\n",
            status.green().bold()
        );
    }
    pub async fn put_user_policy(
        &self,
        iam_user_name: &str,
        policy_name: &str,
        policy_document: &str,
    ) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .put_user_policy()
            .user_name(iam_user_name)
            .policy_name(policy_name)
            .policy_document(policy_document)
            .send()
            .await
            .expect("Error while Performing PutPolicyOperation\n");
        println!(
            "The policy has been added or updated for IAM user {}, as stated in the policy document\n",
            iam_user_name.green().bold()
        );
        println!(
            "{}\n",
            "To delete or detach the inline user policy, select the 'Delete User Policy' option"
                .yellow()
                .bold()
        );
    }
    pub async fn attach_user_policy(&self, iam_user_name: &str, policy_arn: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .attach_user_policy()
            .user_name(iam_user_name)
            .policy_arn(policy_arn)
            .send()
            .await
            .expect("Error While Attaching Managed User Policy\n");
        println!("The provided managed policy with the policy ARN '{}' has been successfully attached to the IAM user '{}'\n",policy_arn.green().bold(),iam_user_name.green().bold());
        println!("{}\n","To add or update an inline policy for an IAM user, select the 'Put User Policy' option".yellow().bold());
        println!("{}\n","To list attached or managed policies for an IAM user, choose the 'List Attached User Policies' option".yellow().bold());
    }
    pub async fn get_user(&self, iam_user_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);

        let output = client
            .get_user()
            .user_name(iam_user_name)
            .send()
            .await
            .expect("Error while getting IAM User Info\n");
        let mut user_table = Table::new();
        user_table
            .set_header(vec![Cell::new("IAM User Details")
                .fg(Color::Yellow)
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Center)])
            .load_preset(UTF8_FULL)
            .set_width(80);
        if let Some(user) = output.user {
            let wrap = UserWrap::wrap(user);
            let user_name = wrap.user_name();
            let user_id = wrap.user_id();
            let create_date = wrap.create_date();
            let arn = wrap.arn();
            let path = wrap.path();
            let password_last_used = wrap.password_last_used();
            if let Some(uname) = user_name {
                let format_uname = format!("IAM User Name: {}", uname);
                user_table.add_row(vec![Cell::new(format_uname)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("IAM User Name: {}", uname.green().bold());
            }
            if let Some(arn) = arn {
                let format_arn = format!("Amazon Resource Name(arn): {}", arn);
                user_table.add_row(vec![Cell::new(format_arn)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //  println!("Amazon Resource Name(arn): {}", arn.green().bold());
            }
            if let Some(id) = user_id {
                let format_id = format!("IAM User ID: {}", id);
                user_table.add_row(vec![Cell::new(format_id)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                // println!("IAM User ID: {}", id.green().bold());
            }
            if let Some(date) = create_date {
                let format_date = format!("User Creation Date and Time: {}", date);
                user_table.add_row(vec![Cell::new(format_date)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                // println!("User Creation Date and Time: {}", date.green().bold());
            }
            if let Some(path) = path {
                let format_path = format!("Path for the IAM User: {}", path);
                user_table.add_row(vec![Cell::new(format_path)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("Path for the IAM User: {}", path.green().bold());
            }
            if let Some(pass) = password_last_used {
                let format_pass_last_used = format!("PassWord Last Used: {}", pass);
                user_table.add_row(vec![Cell::new(format_pass_last_used)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("PassWord Last Used: {}\n\n", pass.green().bold());
            }
        }
        println!("{}", user_table);
        println!(
            "{}\n",
            "To create an IAM user, select the 'Create User' option"
                .yellow()
                .bold()
        );
    }

    pub async fn list_users(&self, path_prefix: Option<String>) -> Vec<String> {
        let config = self.get_config();
        let client = IamClient::new(config);
        let streaming_output = client
            .list_users()
            .set_path_prefix(path_prefix)
            .into_paginator()
            .items()
            .send();
        let outputs = streaming_output
            .collect::<Result<Vec<User>, _>>()
            .await
            .expect("Error while listing IAM users\n");
        let mut user_table = Table::new();
        user_table
            .set_header(vec![Cell::new(
                "At least three IAM user details are displayed",
            )
            .fg(Color::Yellow)
            .add_attribute(Attribute::Bold)
            .set_alignment(CellAlignment::Left)])
            .load_preset(UTF8_FULL)
            .set_width(80);
        outputs.iter().take(3).for_each(|user| {
            let wrap_user = UserWrap::wrap(user.to_owned());
            let user_name = wrap_user.user_name();
            let user_id = wrap_user.user_id();
            let arn = wrap_user.arn();
            let create_date = wrap_user.create_date();
            let password_last_used = wrap_user.password_last_used();
            let path = wrap_user.path();
            if let Some(uname) = user_name {
                let format_uname = format!("IAM User Name: {}", uname);
                user_table.add_row(vec![Cell::new(format_uname)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                // println!("IAM User Name: {}", uname.green().bold());
            }
            if let Some(arn) = arn {
                let format_arn = format!("Amazon Resource Name(arn): {}", arn);
                user_table.add_row(vec![Cell::new(format_arn)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("Amazon Resource Name(arn): {}", arn.green().bold());
            }
            if let Some(id) = user_id {
                let format_id = format!("IAM User ID: {}", id);
                user_table.add_row(vec![Cell::new(format_id)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                // println!("IAM User ID: {}", id.green().bold());
            }
            if let Some(date) = create_date {
                let format_date = format!("User Creation Date and Time: {}", date);
                user_table.add_row(vec![Cell::new(format_date)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                // println!("User Creation Date and Time: {}", date.green().bold());
            }
            if let Some(path) = path {
                let format_path = format!("Path for the IAM User: {}", path);
                user_table.add_row(vec![Cell::new(format_path)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                // println!("Path for the IAM User: {}", path.green().bold());
            }
            if let Some(pass) = password_last_used {
                let format_pass_last_used = format!("PassWord Last Used: {}\n\n", pass);
                user_table.add_row(vec![Cell::new(format_pass_last_used)
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("PassWord Last Used: {}\n\n", pass.green().bold());
            }
            user_table.add_row(vec![Cell::new("\n")]);
        });
        println!("{}", user_table);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open("iam_users_details.txt")
            .expect("Error while creating file\n");
        let mut iam_user_names = Vec::new();
        outputs.into_iter().for_each(|user| {
            let wrap_user = UserWrap::wrap(user);
            let user_name = wrap_user.user_name();
            let user_id = wrap_user.user_id();
            let arn = wrap_user.arn();
            let create_date = wrap_user.create_date();
            let password_last_used = wrap_user.password_last_used();
            let path = wrap_user.path();
            if let Some(uname) = user_name {
                let buf = format!("IAM User Name: {}\n", uname);
                file.write_all(buf.as_bytes()).unwrap();
                iam_user_names.push(uname.to_string());
            }
            if let Some(arn) = arn {
                let buf = format!("IAM User ID: {}\n", arn);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(id) = user_id {
                let buf = format!("IAM User ID: {}\n", id);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(date) = create_date {
                let buf = format!("Creation Date and Time: {}\n", date);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(path) = path {
                let buf = format!("Path for the IAM User: {}\n", path);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(pass) = password_last_used {
                let buf = format!("Password Last Used: {}\n\n", pass);
                file.write_all(buf.as_bytes()).unwrap();
            }
        });
        match File::open("iam_users_details.txt") {
            Ok(_) => println!(
                "All user details are saved to the current directory in a file named {}\n",
                "'iam_users_details.txt'".green().bold()
            ),
            Err(_) => println!("Error while writing Data\n"),
        }

        println!(
            "{}\n",
            "To create an IAM user, select the 'Create User' option"
                .yellow()
                .bold()
        );
        iam_user_names
    }
    pub async fn list_user_policies(&self, iam_user_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);

        let output = client
            .list_user_policies()
            .user_name(iam_user_name)
            .into_paginator()
            .items()
            .send()
            .collect::<Result<Vec<String>, _>>()
            .await
            .expect("Error while listing user policies\n");
        let mut user_table = Table::new();
        user_table
            .set_header(vec![Cell::new(
                "At least five IAM inline user policy names are displayed",
            )
            .fg(Color::Yellow)
            .add_attribute(Attribute::Bold)
            .set_alignment(CellAlignment::Left)])
            .load_preset(UTF8_FULL)
            .set_width(80);
        output.iter().take(5).for_each(|policy| {
            user_table.add_row(vec![Cell::new(format!("Policy: {}", policy))
                .fg(Color::Green)
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Center)]);
            // println!("Policy: {}\n\n", policy.green().bold());
        });
        println!("{}", user_table);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open("iam_inline_user_policies_details.txt")
            .expect("Error while creating file\n");
        output.into_iter().for_each(|policy| {
            let buf = format!("Policy: {}\n", policy);
            file.write_all(buf.as_bytes()).unwrap();
        });
        match File::open("iam_inline_user_policies_details.txt") {
            Ok(_) => println!(
                "All inline user policies are saved to the current directory in a file named: {}\n",
                "iam_inline_user_policies_details.txt'".green().bold()
            ),
            Err(_) => println!("Error while writing Data\n"),
        }
        println!(
            "{}\n",
            "To add or update an inline user policy, select the 'Put User Policy' option"
                .yellow()
                .bold()
        );
        println!(
            "{}\n",
            "To delete the inline user policy, select the 'Delete User Policy' option"
                .yellow()
                .bold()
        );
    }
    pub async fn list_attached_user_policies(
        &self,
        iam_user_name: &str,
        path_prefix: Option<String>,
    ) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let output = client
            .list_attached_user_policies()
            .user_name(iam_user_name)
            .set_path_prefix(path_prefix)
            .into_paginator()
            .items()
            .send()
            .collect::<Result<Vec<AttachedPolicy>, _>>()
            .await
            .expect("Error while listing attached user policies\n");
        let mut policy_table = Table::new();
        policy_table
            .set_header(vec![Cell::new(
                "At least three IAM user-attached policy names and ARNs are displayed",
            )
            .fg(Color::Yellow)
            .add_attribute(Attribute::Bold)
            .set_alignment(CellAlignment::Left)])
            .load_preset(UTF8_FULL)
            .set_width(80);
        output.iter().take(3).for_each(|attached_policy| {
            if let Some(policy_name) = attached_policy.policy_name() {
                policy_table.add_row(vec![Cell::new(format!("Policy Name: {}", policy_name))
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("Policy Name: {}", policy_name.green().bold());
            }
            if let Some(policy_arn) = attached_policy.policy_arn() {
                policy_table.add_row(vec![Cell::new(format!("Policy ARN: {}\n\n", policy_arn))
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("Policy ARN: {}\n\n", policy_arn.green().bold());
            }
        });
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open("iam_attached_user_policies_details.txt")
            .expect("Error while creating file\n");

        output.into_iter().for_each(|attached_policy| {
            if let Some(policy_name) = attached_policy.policy_name() {
                println!("Policy Name: {}", policy_name.green().bold());
                let buf = format!("Policy Name: {policy_name}\n");
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(policy_arn) = attached_policy.policy_arn() {
                println!("Policy ARN: {}\n\n", policy_arn.green().bold());
                let buf = format!("Policy Arn: {policy_arn}\n\n");
                file.write_all(buf.as_bytes()).unwrap();
            }
        });
        match File::open("iam_attached_user_policies_details.txt") {
            Ok(_) => println!(
                "All attached user policies details are saved to the current directory in a file named: {}\n",
                "'iam_attached_user_policies_details.txt'".green().bold()
            ),
            Err(_) => println!("Error while writing Data\n"),
        }
        println!("{}\n", "To delete or detach the attached or managed user policy, select the 'Detach User Policy' option".yellow().bold());
    }
    pub async fn delete_access_key(&self, iam_user_name: &str, access_key: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .delete_access_key()
            .user_name(iam_user_name)
            .access_key_id(access_key)
            .send()
            .await
            .expect("Error while deleting access key\n");
        println!(
            "The access key {} has been deleted\n",
            access_key.bright_green().bold()
        );
        println!(
            "{}\n",
            "To create a new access key, select the 'Create Access Key' option"
                .yellow()
                .bold()
        );
    }
    pub async fn get_policy_name_and_policy_arn_given_iam_user(
        &self,
        iam_user_name: &str,
        path_prefix: Option<String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut policy_names = Vec::new();
        let mut policy_arns = Vec::new();

        let config = self.get_config();
        let client = IamClient::new(config);
        let name_output = client
            .list_user_policies()
            .user_name(iam_user_name)
            .send()
            .await
            .expect("Error while getting Policy Names\n");
        if let Some(policy) = name_output.policy_names {
            policy.into_iter().for_each(|name| {
                policy_names.push(name);
            });
        }
        let arn_output = client
            .list_attached_user_policies()
            .user_name(iam_user_name)
            .set_path_prefix(path_prefix)
            .send()
            .await
            .expect("Error while Getting Policy Arns\n");
        if let Some(policies) = arn_output.attached_policies {
            policies.into_iter().for_each(|policy| {
                if let Some(arn) = policy.policy_arn {
                    policy_arns.push(arn);
                }
            });
        }
        (policy_names, policy_arns)
    }
    pub async fn delete_user_policy(&self, iam_user_name: &str, policy_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .delete_user_policy()
            .user_name(iam_user_name)
            .policy_name(policy_name)
            .send()
            .await
            .expect("Error while deleteing user policy\n");

        println!(
            "The inline policy {} has been deleted for the IAM user {}\n",
            policy_name.bright_green().bold(),
            iam_user_name.bright_green().bold()
        );
        println!(
            "{}\n",
            "To add or update an inline user policy, select the 'Put User Policy' option"
                .yellow()
                .bold()
        );
    }
    pub async fn detatch_user_policy(&self, iam_user_name: &str, policy_arn: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .detach_user_policy()
            .user_name(iam_user_name)
            .policy_arn(policy_arn)
            .send()
            .await
            .expect("Error while Detatching User Policy\n");
        println!("The policy ARN (Amazon Resource Name) {} associated with the IAM user {} has been successfully detached\n",policy_arn.green().bold(),iam_user_name.green().bold());
        println!("{}\n","To list the attached or managed user policies, select the 'List Attached User Policies' option".yellow().bold());
    }
    pub async fn create_group(&self, group_name: &str, path_prefix: Option<String>) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .create_group()
            .group_name(group_name)
            .set_path(path_prefix)
            .send()
            .await
            .expect("Error while creating group\n");

        println!(
            "The group with the Group Name '{}' has been created successfully\n",
            group_name.green().bold()
        );
        println!("{}\n","To obtain information about this group, please use the 'List Groups' option, and to add a user to the group, use the 'Add User To Group' option".yellow().bold());
        println!(
            "{}\n",
            "To delete a group, select the 'Delete Group' option"
                .yellow()
                .bold()
        );
    }
    pub async fn add_user_to_group(&self, group_name: &str, iam_user_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .add_user_to_group()
            .group_name(group_name)
            .user_name(iam_user_name)
            .send()
            .await
            .expect("Error while adding user to group\n");
        println!(
            "The IAM user '{}' has been added to the '{}' group\n",
            iam_user_name.green().bold(),
            group_name.green().bold()
        );
        println!(
            "{}\n",
            "To remove a user from a group, select the 'Remove User From Group' option"
                .yellow()
                .bold()
        );
    }
    pub async fn get_group_names_and_iam_users(&self) -> (Vec<String>, Vec<String>) {
        let mut group_names = Vec::new();

        let config = self.get_config();
        let client = IamClient::new(config);
        let group_output = client
            .list_groups()
            .send()
            .await
            .expect("Error while Getting Group Names\n");

        if let Some(groups) = group_output.groups {
            groups.into_iter().for_each(|group| {
                let group_name = group.group_name;
                if let Some(gname) = group_name {
                    group_names.push(gname);
                }
            })
        }
        let iam_user_names = self.get_iam_users().await;
        (group_names, iam_user_names)
    }
    pub async fn get_group(&self, group_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let outputs = client
            .get_group()
            .group_name(group_name)
            .into_paginator()
            .items()
            .send()
            .collect::<Result<Vec<User>, _>>()
            .await
            .expect("Error while Getting Group information\n");
        let mut group_table = Table::new();
        group_table
            .set_header(vec![Cell::new(
                "At least two IAM user details from the specified user group are displayed",
            )
            .fg(Color::Yellow)
            .add_attribute(Attribute::Bold)
            .set_alignment(CellAlignment::Left)])
            .load_preset(UTF8_FULL)
            .set_width(80);
        outputs.iter().take(2).for_each(|user| {
            let wrap_user = UserWrap::wrap(user.to_owned());
            let user_name = wrap_user.user_name();
            let user_id = wrap_user.user_id();
            let arn = wrap_user.arn();
            let create_date = wrap_user.create_date();
            let password_last_used = wrap_user.password_last_used();
            let path = wrap_user.path();
            if let Some(uname) = user_name {
                group_table.add_row(vec![Cell::new(format!("IAM User Name: {}", uname))
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("IAM User Name: {}", uname.green().bold());
            }
            if let Some(arn) = arn {
                group_table.add_row(vec![Cell::new(format!(
                    "Amazon Resource Name(arn): {}",
                    arn
                ))
                .fg(Color::Green)
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Center)]);
                //println!("Amazon Resource Name(arn): {}", arn.green().bold());
            }
            if let Some(id) = user_id {
                group_table.add_row(vec![Cell::new(format!("IAM User ID: {}", id))
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("IAM User ID: {}", id.green().bold());
            }
            if let Some(date) = create_date {
                group_table.add_row(vec![Cell::new(format!(
                    "User Creation Date and Time: {}",
                    date
                ))
                .fg(Color::Green)
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Center)]);
                //println!("User Creation Date and Time: {}", date.green().bold());
            }
            if let Some(path) = path {
                group_table.add_row(vec![Cell::new(format!("Path for the IAM User: {}", path))
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                // println!("Path for the IAM User: {}", path.green().bold());
            }
            if let Some(pass) = password_last_used {
                group_table.add_row(vec![Cell::new(format!("PassWord Last Used: {}", pass))
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("PassWord Last Used: {}\n\n", pass.green().bold());
            }
        });
        println!("{}", group_table);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open("iam_users_details_in_group.txt")
            .expect("Error while creating file\n");
        outputs.into_iter().for_each(|user| {
            let wrap_user = UserWrap::wrap(user);
            let user_name = wrap_user.user_name();
            let user_id = wrap_user.user_id();
            let arn = wrap_user.arn();
            let create_date = wrap_user.create_date();
            let password_last_used = wrap_user.password_last_used();
            let path = wrap_user.path();
            if let Some(uname) = user_name {
                let buf = format!("IAM User Name: {}\n", uname);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(arn) = arn {
                let buf = format!("IAM User ID: {}\n", arn);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(id) = user_id {
                let buf = format!("IAM User ID: {}\n", id);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(date) = create_date {
                let buf = format!("Creation Date and Time: {}\n", date);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(path) = path {
                let buf = format!("Path for the IAM User: {}\n", path);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(pass) = password_last_used {
                let buf = format!("Password Last Used: {}\n\n", pass);
                file.write_all(buf.as_bytes()).unwrap();
            }
        });
        match File::open("iam_users_details_in_group.txt"){
        Ok(_) =>        println!(
            "{}\n",
            "All user details within the specified group are saved to the current directory in a file named 'iam_users_details_in_group.txt'".green().bold()
        ),
        Err(_) => println!("Error while writing Data\n")          
    }
    }
    pub async fn get_iam_users_in_a_group(&self, group_name: &str) -> Vec<String> {
        let mut iam_users_in_a_group = Vec::new();
        let config = self.get_config();
        let client = IamClient::new(config);
        let output = client
            .get_group()
            .group_name(group_name)
            .into_paginator()
            .items()
            .send()
            .collect::<Result<Vec<User>, _>>()
            .await
            .expect("Error while Getting Group information\n");
        output.into_iter().for_each(|user| {
            if let Some(uname) = user.user_name {
                iam_users_in_a_group.push(uname);
            }
        });
        iam_users_in_a_group
    }
    pub async fn list_groups(&self, path_prefix: Option<String>) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let outputs = client
            .list_groups()
            .set_path_prefix(path_prefix)
            .into_paginator()
            .items()
            .send()
            .collect::<Result<Vec<Group>, _>>()
            .await
            .expect("Error while Listing Groups\n");
        let mut group_table = Table::new();
        group_table
            .set_header(vec![Cell::new(
                "At least three details of IAM Groups are displayed",
            )
            .fg(Color::Yellow)
            .add_attribute(Attribute::Bold)
            .set_alignment(CellAlignment::Left)])
            .load_preset(UTF8_FULL)
            .set_width(80);
        outputs.iter().take(3).for_each(|group| {
            let wrap_group = WrapGroup::wrap(group.to_owned());
            let group_name = wrap_group.group_name();
            let group_id = wrap_group.group_id();
            let arn = wrap_group.group_arn();
            let path = wrap_group.group_path();
            let creation_date = wrap_group.creation_date();
            if let Some(gname) = group_name {
                group_table.add_row(vec![Cell::new(format!("Group Name: {}", gname))
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("Group Name: {}", gname.green().bold());
            }
            if let Some(gid) = group_id {
                group_table.add_row(vec![Cell::new(format!("Group ID: {}", gid))
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("Group ID: {}", gid.green().bold());
            }
            if let Some(arn) = arn {
                group_table.add_row(vec![Cell::new(format!("Group ARN: {}", arn))
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                // println!("Group ARN: {}", arn.green().bold());
            }
            if let Some(path) = path {
                group_table.add_row(vec![Cell::new(format!("Group Path: {}", path))
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("Group Path: {}", path.green().bold());
            }
            if let Some(date) = creation_date {
                group_table.add_row(vec![Cell::new(format!("Creation Date and Time: {}", date))
                    .fg(Color::Green)
                    .add_attribute(Attribute::Bold)
                    .set_alignment(CellAlignment::Center)]);
                //println!("Creation Date and Time: {}\n\n", date.green().bold());
            }
        });
        println!("{}", group_table);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open("list_groups_details.txt")
            .expect("Error while creating file\n");
        outputs.into_iter().for_each(|group| {
            let wrap_group = WrapGroup::wrap(group);
            let group_name = wrap_group.group_name();
            let group_id = wrap_group.group_id();
            let arn = wrap_group.group_arn();
            let path = wrap_group.group_path();
            let creation_date = wrap_group.creation_date();
            if let Some(gname) = group_name {
                println!("Group Name: {}", gname.green().bold());
                let buf = format!("Group Name: {}\n", gname);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(gid) = group_id {
                println!("Group ID: {}", gid.green().bold());
                let buf = format!("Group ID: {}\n", gid);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(arn) = arn {
                println!("Group ARN: {}", arn.green().bold());
                let buf = format!("Group ARN: {}\n", arn);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(path) = path {
                println!("Group Path: {}", path.green().bold());
                let buf = format!("Group Path: {}\n", path);
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(date) = creation_date {
                println!("Creation Date and Time: {}\n\n", date.green().bold());
                let buf = format!("Group Creation Date and Time: {}\n", date);
                file.write_all(buf.as_bytes()).unwrap();
            }
        });
        match File::open("list_groups_details.txt"){
            Ok(_) =>        println!(
                "{}\n",
                "All group details are saved to the current directory in a file named 'list_groups_details.txt'".green().bold()
            ),
            Err(_) => println!("Error while writing Data\n")
}
        println!(
            "{}\n",
            "To create a group, select the 'Create Group' option"
                .yellow()
                .bold()
        );
        println!(
            "{}\n",
            "To delete a group, select the 'Delete Group' option"
                .yellow()
                .bold()
        );
    }
    pub async fn put_group_policy(
        &self,
        group_name: &str,
        policy_name: &str,
        policy_document: &str,
    ) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .put_group_policy()
            .group_name(group_name)
            .policy_name(policy_name)
            .policy_document(policy_document)
            .send()
            .await
            .expect("Error while Creating Inline Group Policy\n");
        println!("The inline policy named {} with the specified policy document has been added or updated in the specified group named {}\n",policy_name.green().bold(),group_name.green().bold());
        println!(
            "{}\n",
            "To delete the inline group policy, choose the 'Delete Group Policy' option\n"
                .yellow()
                .bold()
        );
    }
    pub async fn attach_group_policy(&self, group_name: &str, policy_arn: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .attach_group_policy()
            .group_name(group_name)
            .policy_arn(policy_arn)
            .send()
            .await
            .expect("Error while Attaching Managed Group Policy\n");

        println!("The provided managed policy with the policy ARN '{}' has been successfully attached to the group '{}'\n",policy_arn.green().bold(),group_name.green().bold());
        println!(
            "{}\n",
            "To add or update an inline policy for a group, choose the 'Put Group Policy' option"
                .yellow()
                .bold()
        );
        println!("{}\n","To list attached or managed policies for a group, choose the 'List Attached Group Policies' option".yellow().bold());
    }
    pub async fn list_group_policies(&self, group_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let outputs = client
            .list_group_policies()
            .group_name(group_name)
            .into_paginator()
            .items()
            .send()
            .collect::<Result<Vec<String>, _>>()
            .await
            .expect("Error while listing group policies\n");
        let mut group_policy_table = Table::new();
        group_policy_table
            .set_header(vec![Cell::new(
                "At least five inline Group Policy names are displayed",
            )
            .fg(Color::Yellow)
            .add_attribute(Attribute::Bold)
            .set_alignment(CellAlignment::Left)])
            .load_preset(UTF8_FULL)
            .set_width(80);
        outputs.iter().take(5).for_each(|policy_name| {
            group_policy_table.add_row(vec![Cell::new(format!("Policy Name: {}", policy_name))
                .fg(Color::Green)
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Center)]);
            //println!("Policy Name: {}\n\n", policy_name.green().bold());
        });
        println!("{}", group_policy_table);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open("inline_group_policy_names.txt")
            .expect("Error while creating file\n");
        outputs.into_iter().for_each(|policy_name| {
            let buf = format!("Policy Name: {}\n", policy_name);
            file.write_all(buf.as_bytes()).unwrap();
        });
        match File::open("inline_group_policy_names.txt"){
            Ok(_) =>        println!(
                "{}\n",
                "All the inline group policy names have been written to the current directory with the name 'inline_group_policy_names.txt'".green().bold()
            ),
            Err(_) => println!("Error while writing Data\n")
}
        println!(
            "{}\n",
            "To create the inline group policy, select the 'Put Group Policy' option"
                .yellow()
                .bold()
        );
        println!(
            "{}\n",
            "To delete inline group policy, select the 'Delete Group Policy' option"
                .yellow()
                .bold()
        );
    }
    pub async fn list_attached_group_policies(
        &self,
        group_name: &str,
        path_prefix: Option<String>,
    ) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let outputs = client
            .list_attached_group_policies()
            .group_name(group_name)
            .set_path_prefix(path_prefix)
            .into_paginator()
            .items()
            .send()
            .collect::<Result<Vec<AttachedPolicy>, _>>()
            .await
            .expect("Error while Listing Attached Group Polices\n");
        let mut group_policy_table = Table::new();
        group_policy_table
            .set_header(vec![Cell::new(
            "At least three attached or managed Group Policy names and ARN details are displayed",
        )
        .fg(Color::Yellow)
        .add_attribute(Attribute::Bold)
        .set_alignment(CellAlignment::Left)])
            .load_preset(UTF8_FULL)
            .set_width(80);
        outputs.iter().take(3).for_each(|attached_policy| {
            let policy_arn = attached_policy.policy_arn();
            let policy_name = attached_policy.policy_name();
            if let Some(policy_name) = policy_name {
                group_policy_table.add_row(vec![Cell::new(format!(
                    "Policy Name: {}",
                    policy_name
                ))
                .fg(Color::Green)
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Center)]);
                //println!("Policy Name: {}", policy_name.green().bold());
            }
            if let Some(policy_arn) = policy_arn {
                group_policy_table.add_row(vec![Cell::new(format!(
                    "Policy Arn: {}\n\n",
                    policy_arn
                ))
                .fg(Color::Green)
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Center)]);
                //println!("Policy Arn: {}\n\n", policy_arn.green().bold());
            }
            group_policy_table.add_row(vec![Cell::new("\n")]);
        });
        println!("{}", group_policy_table);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open("attached_group_policy_details.txt")
            .expect("Error while creating file\n");
        outputs.into_iter().take(3).for_each(|attached_policy| {
            let policy_arn = attached_policy.policy_arn;
            let policy_name = attached_policy.policy_name;
            if let Some(policy_name) = policy_name {
                let buf = format!("Policy Name: {policy_name}\n");
                file.write_all(buf.as_bytes()).unwrap();
            }
            if let Some(policy_arn) = policy_arn {
                let buf = format!("Policy Arn: {policy_arn}\n");
                file.write_all(buf.as_bytes()).unwrap();
            }
        });
        match File::open("attached_group_policy_details.txt"){
            Ok(_) =>        println!(
                "{}\n",
                "All the attached group policy details have been written to the current directory with the name 'attached_group_policy_details.txt'".green().bold()
            ),
            Err(_) => println!("Error while writing Data\n")
}
        println!(
            "{}\n",
            "To list the inline policies for a group, use 'List Group Policies'"
                .yellow()
                .bold()
        );

        println!("{}\n","To delete or detach the attached or managed group policy, select the 'Detach Group Policy' option\n".yellow().bold());
    }

    pub async fn remove_user_from_group(&self, group_name: &str, iam_user_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .remove_user_from_group()
            .group_name(group_name)
            .user_name(iam_user_name)
            .send()
            .await
            .expect("Error while removing user from a group\n");
        println!(
            "The IAM user {} has been removed from the group named {}\n",
            iam_user_name.bright_green().bold(),
            group_name.bright_green().bold()
        );
        println!(
            "{}\n",
            "To add a user to a group, select the 'Add User To Group' option"
                .yellow()
                .bold()
        );
        println!(
            "{}\n",
            "To list the available users in a group, select the 'Get Group' option"
                .yellow()
                .bold()
        );
    }
    pub async fn get_group_inline_policy_name_and_attached_policy_arn(
        &self,
        group_name: &str,
    ) -> (Vec<String>, Vec<String>) {
        let mut group_policy_names = Vec::new();
        let mut group_policy_arns = Vec::new();

        let config = self.get_config();
        let client = IamClient::new(config);
        let name_outputs = client
            .list_group_policies()
            .group_name(group_name)
            .into_paginator()
            .items()
            .send()
            .collect::<Result<Vec<String>, _>>()
            .await
            .expect("Error while listing group policies\n");

        name_outputs.into_iter().for_each(|policy_name| {
            group_policy_names.push(policy_name);
        });

        let arn_outputs = client
            .list_attached_group_policies()
            .group_name(group_name)
            .into_paginator()
            .items()
            .send()
            .collect::<Result<Vec<AttachedPolicy>, _>>()
            .await
            .expect("Error while Listing Attached Group Polices\n");

        arn_outputs.into_iter().for_each(|policies| {
            if let Some(policy_arn) = policies.policy_arn {
                group_policy_arns.push(policy_arn);
            }
        });

        (group_policy_names, group_policy_arns)
    }
    pub async fn delete_group_policy(&self, group_name: &str, policy_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .delete_group_policy()
            .group_name(group_name)
            .policy_name(policy_name)
            .send()
            .await
            .expect("Error while deleting inline group policy\n");
        println!(
            "The policy named {} has been removed from the group named {}\n",
            policy_name.bright_green().bold(),
            group_name.bright_green().bold()
        );

        println!(
            "{}\n",
            "To create the inline group policy, select the 'Put Group Policy' option"
                .yellow()
                .bold()
        );
        println!(
            "{}\n",
            "To list inline group policies, select the 'List Group Policies' option"
                .yellow()
                .bold()
        );
    }
    pub async fn detach_group_policy(&self, group_name: &str, policy_arn: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .detach_group_policy()
            .group_name(group_name)
            .policy_arn(policy_arn)
            .send()
            .await
            .expect("Error while detaching attached group policy\n");
        println!("The policy with the ARN {} which was associated with an attached or managed policy, has been detached from the group named {}",policy_arn.bright_green().bold(),group_name.bright_green().bold());

        println!("{}\n","To list the attached or managed group policies, select the 'List Attached Group Policies' option\n".yellow().bold());
    }
    pub async fn delete_group(&self, group_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        client
            .delete_group()
            .group_name(group_name)
            .send()
            .await
            .expect("Error while deleting Group\n");
        println!(
            "The group name '{}' has been deleted\n",
            group_name.bright_green().bold()
        );
        println!(
            "{}\n",
            "To create a group, select the 'Create Group' option"
                .yellow()
                .bold()
        );
        println!(
            "{}\n",
            "To List a group, select the 'List Groups' option"
                .yellow()
                .bold()
        );
    }
    pub async fn get_role(&self, role_name: &str) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let outputs = client
            .get_role()
            .role_name(role_name)
            .send()
            .await
            .expect("Error while Getting Role\n");
        let mut role_table = Table::new();
        role_table
            .set_header(vec![Cell::new("Role Details")
                .fg(Color::Yellow)
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Left)])
            .load_preset(UTF8_FULL)
            .set_width(80);
        if let Some(role_details) = outputs.role {
            if let Some(role_id) = role_details.role_id {
                role_table.add_row(vec![Cell::new(format!("Role ID: {}", role_id))
                    .fg(Color::Green)
                    .set_alignment(CellAlignment::Center)
                    .add_attribute(Attribute::Bold)]);
                //println!("Role ID: {}", role_id.green().bold());
            }
            if let Some(role_arn) = role_details.arn {
                role_table.add_row(vec![Cell::new(format!("Role Arn: {}", role_arn))
                    .fg(Color::Green)
                    .set_alignment(CellAlignment::Center)
                    .add_attribute(Attribute::Bold)]);
                // println!("Role Arn: {}", role_arn.green().bold());
            }
            if let Some(path) = role_details.path {
                role_table.add_row(vec![Cell::new(format!("Role Path: {}", path))
                    .fg(Color::Green)
                    .set_alignment(CellAlignment::Center)
                    .add_attribute(Attribute::Bold)]);
                //println!("Role Path: {}", path.green().bold());
            }
            if let Some(description) = role_details.description {
                role_table.add_row(vec![Cell::new(format!(
                    "Description of Role: {}",
                    description
                ))
                .fg(Color::Green)
                .set_alignment(CellAlignment::Center)
                .add_attribute(Attribute::Bold)]);
                //println!("Description of Role: {}", description.green().bold());
            }
            if let Some(create_date) = role_details.create_date {
                let convert_time = create_date.fmt(DateTimeFormat::HttpDate).ok();
                if let Some(time) = convert_time {
                    role_table.add_row(vec![Cell::new(format!(
                        "Creation Date and Time: {}",
                        time
                    ))
                    .fg(Color::Green)
                    .set_alignment(CellAlignment::Center)
                    .add_attribute(Attribute::Bold)]);
                    // println!("Creation Date and Time: {}", time.green().bold());
                }
            }
            if let Some(assume_doc) = role_details.assume_role_policy_document {
                let decode_policy_document = decode(assume_doc);
                let mut file = OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .open("AssumePolicyDocument.json")
                    .expect("Error while creating file\n");
                file.write_all(decode_policy_document.as_bytes()).unwrap();
                match File::open("AssumePolicyDocument.json") {
                    Ok(_) => println!("The 'Assume Policy Document' has been written to the current directory as '{}'","AssumePolicyDocument.json".green().bold()),
                    Err(_) => println!(
                        "{}\n",
                        "Error while writing Assume Policy data".red().bold()
                    ),
                }
            }
            if let Some(permission_boundary) = role_details.permissions_boundary {
                if let Some(policy_arn) = permission_boundary.permissions_boundary_arn {
                    role_table.add_row(vec![Cell::new(format!(
                        "Permission Boundary Arn: {}",
                        policy_arn
                    ))
                    .fg(Color::Green)
                    .set_alignment(CellAlignment::Center)
                    .add_attribute(Attribute::Bold)]);
                    //   println!("Permission Boundary Arn: {}", policy_arn.green().bold());
                }
                if let Some(policy_type) = permission_boundary.permissions_boundary_type {
                    let type_ = policy_type.as_str();
                    role_table.add_row(vec![Cell::new(format!(
                        "Permission Boundary Attachment Type: {}",
                        type_
                    ))
                    .fg(Color::Green)
                    .set_alignment(CellAlignment::Center)
                    .add_attribute(Attribute::Bold)]);
                }
            }
            if let Some(max_duration) = role_details.max_session_duration {
                role_table.add_row(vec![Cell::new(format!(
                    "The maximum session duration (in hours) for the specified role: {}",
                    (max_duration / (60 * 60))
                ))
                .fg(Color::Green)
                .set_alignment(CellAlignment::Center)
                .add_attribute(Attribute::Bold)]);
            }
            if let Some(last_used_deatils) = role_details.role_last_used {
                if let Some(region) = last_used_deatils.region {
                    role_table.add_row(vec![Cell::new(format!("Last Used Region: {}", region))
                        .fg(Color::Green)
                        .set_alignment(CellAlignment::Center)
                        .add_attribute(Attribute::Bold)]);
                    // println!("Last Used Region: {}", region.green().bold());
                }
                if let Some(time) = last_used_deatils.last_used_date {
                    let convert = time.fmt(DateTimeFormat::HttpDate).ok();
                    if let Some(time) = convert {
                        role_table.add_row(vec![Cell::new(format!("Role Last Used: {}\n", time))
                            .fg(Color::Green)
                            .set_alignment(CellAlignment::Center)
                            .add_attribute(Attribute::Bold)]);
                        //println!("Role Last Used: {}\n", time.green().bold());
                    }
                }
            }
        }
        println!("{}", role_table);
    }
    pub async fn get_account_autherization_details(&self) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let autherization_details = client.get_account_authorization_details().send().await;
        match autherization_details {
            Ok(autherization_details) => {
                let user_detail_list = autherization_details.user_detail_list;
                let group_detail_list = autherization_details.group_detail_list;
                let role_detail_list = autherization_details.role_detail_list;
                let policies = autherization_details.policies;
                if let (Some(users), Some(groups), Some(roles), Some(policies)) = (
                    user_detail_list,
                    group_detail_list,
                    role_detail_list,
                    policies,
                ) {
                    let mut write_to = OpenOptions::new()
                        .create(true)
                        .read(true)
                        .write(true)
                        .open("Account_Authorization_Details.txt")
                        .expect("Error while creating file\n");
                    write_to.write_all("{\n".as_bytes()).unwrap();
                    users.into_iter().for_each(|userdetail| {
                        let mut wrap_user_detail = WrapUserDetail::wrap(userdetail);
                        wrap_user_detail.write_user_detail(&mut write_to);
                    });
                    write_to.write_all("}\n".as_bytes()).unwrap();
                    write_to.write_all("{\n".as_bytes()).unwrap();
                    groups.into_iter().for_each(|groupdetail| {
                        let mut wrap_group_detail = WrapGroupDetail::wrap(groupdetail);
                        wrap_group_detail.write_group_detail(&mut write_to);
                    });
                    write_to.write_all("}\n".as_bytes()).unwrap();
                    write_to.write_all("{\n".as_bytes()).unwrap();
                    roles.into_iter().for_each(|role_detail| {
                        let mut wrap_role_detail = WrapRoleDetail::wrap(role_detail);
                        wrap_role_detail.write_role_detail(&mut write_to);
                    });
                    write_to.write_all("}\n".as_bytes()).unwrap();
                    write_to.write_all("{\n".as_bytes()).unwrap();
                    policies.into_iter().for_each(|managedpolicydetail| {
                        let mut wrap_managed_policy_detail =
                            WrapManagedPolicyDetail::wrap(managedpolicydetail);
                        wrap_managed_policy_detail.write_managed_policy_detail(&mut write_to);
                    });
                    write_to.write_all("}\n".as_bytes()).unwrap();
                }

                println!("All the Account Authorization details are written to the current directory with the name '{}'\n" ,"Account_Authorization_Details.txt".green().bold());
            }
            Err(_) => {
                let error_msg1 ="1. You may have forgotten to execute the 'Verify the Credentials' option before running this one".bright_red().bold();
                let error_msg2 = "2. The credentials you provided may be invalid. Please double-check and ensure that you have the correct credentials".bright_red().bold();
                println!("Some possible scenarios for the operation failure are as follows\n{error_msg1}\n{error_msg2}\n");
            }
        }
    }
    pub async fn generate_credential_report(&self) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let outputs = client.generate_credential_report().send().await;
        match outputs {
            Ok(outputs) => {
                let status = outputs.state;
                let description = outputs.description;
                if let (Some(status), Some(description)) = (status, description) {
                    let status = status.as_str();
                    println!("Status of Credential Report: {}\n", status.green().bold());
                    println!(
                        "Description of the Credential Report: {}\n",
                        description.green().bold()
                    );
                }
                println!("{}\n","Please note that you should not expect a credential report without first executing the 'Generate Credential Report' option".yellow().bold());
                println!("{}\n","Additionally, the 'Get Credential Report' option will only return the credential report when the status is marked as 'COMPLETE.".yellow().bold());
            }
            Err(_) => {
                let error_msg1 ="1. You may have forgotten to execute the 'Verify the Credentials' option before running this one".bright_red().bold();
                let error_msg2 = "2. The credentials you provided may be invalid. Please double-check and ensure that you have the correct credentials".bright_red().bold();
                println!("Some possible scenarios for the operation failure are as follows\n{error_msg1}\n{error_msg2}\n");
            }
        }
    }
    pub async fn get_credential_report(&self) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let cred_report = client.get_credential_report().send().await;
        match cred_report {
            Ok(cred_report) => {
                let wrap_cred_report = WrapCredReport::wrap(cred_report);
                let report_format = wrap_cred_report.report_format();
                let generated_time = wrap_cred_report.generated_time();
                if let (Some(format), Some(time)) = (report_format, generated_time) {
                    println!(
                        "The Format of the Credential Report: {}\n",
                        format.green().bold()
                    );
                    println!(
                        "Generated Time of the Credential Report: {}\n",
                        time.green().bold()
                    );
                }
                wrap_cred_report.credential_content();
                println!(
                    "{}\n",
                    "Use a CsvViewer to obtain visually appealing data views"
                        .yellow()
                        .bold()
                );
            }
            Err(_) => {
                let error_msg1 = "1. You may have forgotten to execute the 'Verify the Credentials' option before running this one".bright_red().bold();
                let error_msg2 = "2. You may have forgotten to call the 'Generate Credential Report' option before executing this one".bright_red().bold();
                let error_msg3 ="3. The status may be in the 'STARTED' or 'INPROGRESS' state, as the credential report is only available in the 'COMPLETE' state".bright_red().bold();
                println!("Some possible scenarios for the operation failure are as follows:\n{error_msg1}\n{error_msg2}\n{error_msg3}\n");
            }
        }
    }
    pub async fn get_account_summary(&self) {
        let config = self.get_config();
        let client = IamClient::new(config);
        let outputs = client.get_account_summary().send().await;
        match outputs {
            Ok(outputs) => {
                let wrap_account_summary = WrapAccountSummary::wrap(outputs);
                wrap_account_summary.summary_map();
            }
            Err(_) => {
                let error_msg1 ="1. You may have forgotten to execute the 'Verify the Credentials' option before running this one".bright_red().bold();
                let error_msg2 = "2. The credentials you provided may be invalid. Please double-check and ensure that you have the correct credentials".bright_red().bold();
                println!("Some possible scenarios for the operation failure are as follows\n{error_msg1}\n{error_msg2}\n");
            }
        }
    }
}
pub struct UserWrap(User);
impl UserWrap {
    pub fn wrap(type_: User) -> Self {
        Self(type_)
    }
    pub fn arn(&self) -> Option<&str> {
        self.0.arn()
    }
    pub fn path(&self) -> Option<&str> {
        self.0.path()
    }
    pub fn user_id(&self) -> Option<&str> {
        self.0.user_id()
    }
    pub fn user_name(&self) -> Option<&str> {
        self.0.user_name()
    }
    pub fn create_date(&self) -> Option<String> {
        self.0
            .create_date()
            .map(|date| date.fmt(DateTimeFormat::HttpDate))
            .map(|get_inner| get_inner.ok())
            .flatten()
    }
    pub fn password_last_used(&self) -> Option<String> {
        self.0
            .password_last_used()
            .map(|date| date.fmt(DateTimeFormat::HttpDate))
            .map(|get_inner| get_inner.ok())
            .flatten()
    }
}
pub struct WrapAccessKey(AccessKey);
impl WrapAccessKey {
    pub fn wrap(type_: AccessKey) -> Self {
        Self(type_)
    }
    pub fn user_name(&self) -> Option<&str> {
        self.0.user_name()
    }
    pub fn access_key(&self) -> Option<&str> {
        self.0.access_key_id()
    }
    pub fn secret_access_key(&self) -> Option<&str> {
        self.0.secret_access_key()
    }
    pub fn status(&self) -> Option<&str> {
        self.0.status().map(|status| status.as_str())
    }
    pub fn create_date(&self) -> Option<String> {
        self.0
            .create_date()
            .map(|date| date.fmt(DateTimeFormat::HttpDate))
            .map(|get_inner| get_inner.ok())
            .flatten()
    }
}
pub struct WrapGroup(Group);
impl WrapGroup {
    fn wrap(type_: Group) -> Self {
        Self(type_)
    }
    fn group_name(&self) -> Option<&str> {
        self.0.group_name()
    }
    fn group_id(&self) -> Option<&str> {
        self.0.group_id()
    }
    fn group_arn(&self) -> Option<&str> {
        self.0.arn()
    }
    fn group_path(&self) -> Option<&str> {
        self.0.path()
    }
    fn creation_date(&self) -> Option<String> {
        self.0
            .create_date()
            .map(|date| date.fmt(DateTimeFormat::HttpDate))
            .map(|get_inner| get_inner.ok())
            .flatten()
    }
}
pub struct WrapCredReport(GetCredentialReportOutput);
impl WrapCredReport {
    fn wrap(type_: GetCredentialReportOutput) -> Self {
        Self(type_)
    }
    fn credential_content(self) {
        let blob_content = self.0.content;
        if let Some(content) = blob_content {
            let vec_of_bytes = content.into_inner();
            let content_ = String::from_utf8(vec_of_bytes);
            match content_ {
                Ok(credential_report) => {
                    let mut file = OpenOptions::new()
                        .create(true)
                        .read(true)
                        .write(true)
                        .open("credential_reports.csv")
                        .expect("Error while creating credential report\n");
                    match file.write_all(credential_report.as_bytes()) {
                   Ok(_) =>{
                    println!("{}\n","The credential report has been generated and saved to the current directory under the name 'credential_report.csv.'".green().bold());
                    pdf_writer::generate_credential_report_pdf(&credential_report);
                   }
                   Err(_) => println!("Error while writting credential data")
                    }
                }
                Err(_) => println!("{}\n","An error has occurred while attempting to construct a string data from a vector of bytes obtained from the blob type".bright_red().bold()),
            }
        }
    }
    fn report_format(&self) -> Option<&str> {
        self.0.report_format().map(|format| format.as_str())
    }
    fn generated_time(&self) -> Option<String> {
        self.0
            .generated_time()
            .map(|time| time.fmt(DateTimeFormat::HttpDate))
            .map(|get_inner| get_inner.ok())
            .flatten()
    }
}
pub struct WrapAccountSummary(GetAccountSummaryOutput);
impl WrapAccountSummary {
    fn wrap(type_: GetAccountSummaryOutput) -> Self {
        Self(type_)
    }
    fn summary_map(self) {
        if let Some(summary_map) = self.0.summary_map {
            let mut file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open("Account_Summary.txt")
                .expect("Error while creating credential report\n");
            summary_map.iter().for_each(|(iam_entity, quotas)| {
                let iam_entity_usage = iam_entity.as_str();
                let buf = format!("IAM Entity: {iam_entity_usage} and Quotas: {quotas}\n");
                file.write_all(buf.as_bytes())
                    .expect("Error while writing data\n");
            });
            pdf_writer::get_account_summary_pdf(summary_map);
            match File::open("Account_Summary.txt") {
                Ok(_) => println!("The account summary has been saved to the current directory with the filename {}\n","Account_Summary.txt".green().bold()),
                Err(_) => println!("Error while writting data\n")
            }
        }
    }
}
pub struct WrapUserDetail(UserDetail);
impl WrapUserDetail {
    fn wrap(type_: UserDetail) -> Self {
        Self(type_)
    }
    pub fn date(&self) -> Option<String> {
        self.0
            .create_date()
            .map(|date| date.fmt(DateTimeFormat::HttpDate))
            .map(|get_inner| get_inner.ok())
            .flatten()
    }
    fn write_user_policy_detail(&mut self, write_to: &mut File) {
        if let Some(policy_detail) = self.0.user_policy_list.take() {
            write_to
                .write_all("User Policy Details:\n\n".as_bytes())
                .unwrap();
            policy_detail.into_iter().for_each(|policy| {
                if let (Some(policy_name), Some(policy_doc)) =
                    (policy.policy_name, policy.policy_document)
                {
                    //https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html
                    let decode_policy_document = decode(policy_doc);
                    let buf = format!(
                        "Policy Name: {policy_name}\nPolicy Document:{decode_policy_document}\n\n"
                    );
                    write_to
                        .write_all(buf.as_bytes())
                        .expect("Error while writting User Policy Detail");
                    {}
                }
            });
        }
    }
    fn write_group_list(&mut self, write_to: &mut File) {
        if let Some(group_lists) = self.0.group_list.take() {
            write_to
                .write_all("Group List Names\n\n".as_bytes())
                .unwrap();
            group_lists.into_iter().for_each(|mut glist| {
                write_to
                    .write_all(glist.as_bytes())
                    .expect("Error while writting group list");
                glist.push('\n');
            });
        }
    }
    fn write_attached_policy(&mut self, write_to: &mut File) {
        if let Some(attached_policy) = self.0.attached_managed_policies.take() {
            write_to
                .write_all("Attached/Managed Policies\n\n".as_bytes())
                .unwrap();
            attached_policy.into_iter().for_each(|attached| {
                if let (Some(pname), Some(parn)) = (attached.policy_name, attached.policy_arn) {
                    let buf = format!("Policy Name: {pname}\nPolicy ARN: {parn}\n");
                    write_to
                        .write_all(buf.as_bytes())
                        .expect("Error while writting attached Policy\n");
                }
            });
        }
    }
    fn write_attached_permission_boundary(&mut self, write_to: &mut File) {
        if let Some(permission_boundary) = self.0.permissions_boundary.take() {
            if let (Some(boundary_arn), Some(boundary_type)) = (
                permission_boundary.permissions_boundary_arn,
                permission_boundary.permissions_boundary_type,
            ) {
                write_to
                    .write_all("Permissions Boundary\n\n".as_bytes())
                    .unwrap();
                let boundary_type = boundary_type.as_str();
                let buf = format!("Permissions Boundary Type: {boundary_type}\nPermissions Boundary Arn: {boundary_arn}\n");
                write_to
                    .write_all(buf.as_bytes())
                    .expect("Error while writting Permission Boundary\n");
            }
        }
    }
    fn write_tags(&mut self, write_to: &mut File) {
        if let Some(tags) = self.0.tags.take() {
            write_to.write_all("IAM User Tags\n\n".as_bytes()).unwrap();
            tags.into_iter().for_each(|tag| {
                if let (Some(key), Some(value)) = (tag.key, tag.value) {
                    let buf = format!("Key: {key}\nvalue: {value}\n");
                    write_to
                        .write_all(buf.as_bytes())
                        .expect("Error while writing Tags\n");
                }
            });
        }
    }

    pub fn write_user_detail(&mut self, write_to: &mut File) {
        if let (Some(uname), Some(uid), Some(arn), Some(path), Some(date)) = (
            self.0.user_name.take(),
            self.0.user_id.take(),
            self.0.arn.take(),
            self.0.path.take(),
            self.date(),
        ) {
            let user_name = format!("User details, data as received from https://tinyurl.com/596ftxfs\n\n\n\nIAM User Name: {uname}\nIAM User ID: {uid}\nUser ARN: {arn}\nUser Path: {path}\nUser Creation Date and Time: {date}\n\n",);
            write_to.write_all(user_name.as_bytes()).unwrap();
            self.write_user_policy_detail(write_to);
            self.write_group_list(write_to);
            self.write_attached_policy(write_to);
            self.write_attached_permission_boundary(write_to);
            self.write_tags(write_to);
        };
    }
}
pub struct WrapGroupDetail(GroupDetail);
impl WrapGroupDetail {
    fn wrap(type_: GroupDetail) -> Self {
        Self(type_)
    }
    fn create_date(&self) -> Option<String> {
        self.0
            .create_date()
            .map(|date| date.fmt(DateTimeFormat::HttpDate))
            .map(|get_inner| get_inner.ok())
            .flatten()
    }
    fn write_group_policy_list(&mut self, write_to: &mut File) {
        if let Some(policy_detail) = self.0.group_policy_list.take() {
            write_to
                .write_all("Group Policy List\n\n".as_bytes())
                .unwrap();
            policy_detail.into_iter().for_each(|policy_inner| {
                if let (Some(pname), Some(pdoc)) =
                    (policy_inner.policy_name, policy_inner.policy_document)
                {
                    let decode_policy_document = decode(pdoc);
                    let buf = format!(
                        "Policy Name: {pname}\n\nPolicy Document: {decode_policy_document}\n\n"
                    );
                    write_to
                        .write_all(buf.as_bytes())
                        .expect("Error while writing group policy list");
                }
            });
        }
    }
    fn write_attached_managed_policies(&mut self, write_to: &mut File) {
        if let Some(attached_policies) = self.0.attached_managed_policies.take() {
            write_to
                .write_all("Attached Managed Policies\n\n".as_bytes())
                .unwrap();
            attached_policies.into_iter().for_each(|policy_detail| {
                if let (Some(pname), Some(parn)) =
                    (policy_detail.policy_name, policy_detail.policy_arn)
                {
                    let buf = format!("Policy Name: {pname}\nPolicy Arn: {parn}\n");
                    write_to
                        .write_all(buf.as_bytes())
                        .expect("Error while writing attached managed policies\n");
                }
            });
        }
    }
    fn write_group_detail(&mut self, write_to: &mut File) {
        if let (Some(gname), Some(gid), Some(arn), Some(path), Some(date)) = (
            self.0.group_name.take(),
            self.0.group_id.take(),
            self.0.arn.take(),
            self.0.path.take(),
            self.create_date(),
        ) {
            let buf = format!("Group details, data as received from https://tinyurl.com/52wvzwp6\n\n\n\nGroup Name: {gname}\nGroup ID: {gid}\nGroup Arn: {arn}\nGroup Path: {path}\nGroup Creation Date and Time: {date}\n");
            write_to
                .write_all(buf.as_bytes())
                .expect("Error while writing Group Details\n");
            self.write_group_policy_list(write_to);
            self.write_attached_managed_policies(write_to);
        }
    }
}
pub struct WrapRoleDetail(RoleDetail);
impl WrapRoleDetail {
    fn wrap(type_: RoleDetail) -> Self {
        Self(type_)
    }
    fn create_date(&self) -> Option<String> {
        self.0
            .create_date()
            .map(|date| date.fmt(DateTimeFormat::HttpDate))
            .map(|get_inner| get_inner.ok())
            .flatten()
    }
    fn write_instance_profile_list(&mut self, write_to: &mut File) {
        if let Some(insatnce_profile) = self.0.instance_profile_list.take() {
            write_to
                .write_all("Instance Profile List\n\n".as_bytes())
                .unwrap();
            insatnce_profile.into_iter().for_each(|profile| {
                let str_format_of_date = profile.create_date.map(|date|date.fmt(DateTimeFormat::HttpDate).ok()).flatten();
                if let (
                    Some(profile_name),
                    Some(profile_id),
                    Some(arn),
                    Some(path),
                    Some(date),
                    Some(roles),
                    Some(tags),
                ) = (
                    profile.instance_profile_name,
                    profile.instance_profile_id,
                    profile.arn,
                    profile.path,
                    str_format_of_date,
                    profile.roles,
                    profile.tags,
                ) {
                   let buf = format!("Instance Profile Name: {profile_name}\nInstance Profile ID: {profile_id}\nInstance Profile Arn: {arn}\nInstance Profile Path: {path}\nInstance Profile Creation Date and Time: {date}\n"); 
                   write_to.write_all(buf.as_bytes()).expect("Error while writing Instance Profile Info part 1\n");
                   write_to.write_all("Role Details\n\n".as_bytes()).unwrap();
                   roles.into_iter()
                   .for_each(|role|{
                    let date_time = role.create_date.map(|date|date.fmt(DateTimeFormat::HttpDate).ok()).flatten();
                    let permissions_boundary = role.permissions_boundary.map(|boundary|{
                        let boundary_type = boundary.permissions_boundary_type.map(|type_|type_.as_str().to_string());
                        let boundary_arn =boundary.permissions_boundary_arn;
                        (boundary_type,boundary_arn)
                    });
                    let role_last_used = role.role_last_used.map(|role_used|{
                        let last_used_date = role_used.last_used_date.map(|str_format|str_format.fmt(DateTimeFormat::HttpDate).ok()).flatten();
                        let region = role_used.region;
                        (last_used_date,region)
                    });
                    if let (Some(rname),Some(rid),Some(arn),
                    Some(path),Some(date),Some(assume_role),
                    Some(descrip),Some(max),Some((Some(boundary_type),
                    Some(boundary_arn))),Some(tags),Some((Some(last_used),
                    Some(region)))) =
                    (role.role_name,role.role_id,role.arn,role.path,
                    date_time,role.assume_role_policy_document,role.description,
                    role.max_session_duration,permissions_boundary,role.tags,role_last_used){
                    let decode_policy_document = decode(assume_role);
                    let buf = format!("Role Name: {rname}\nRole ID: {rid}\nRole Arn: {arn}\nRole Path: {path}\nRole Creation Date and Time: {date}\nAssume Role Policy Document: {decode_policy_document}\nDescirption: {descrip}\nMaximum Session Duration: {max}\nPermission Boundary\nPermission Boundary Type: {boundary_type}\nPermission Boundary Arn: {boundary_arn}\nRole Tags: {tags:#?}\nRole Usage\nRole Last Used: {last_used}\nRole Region: {region}\n");
                    write_to.write_all(buf.as_bytes()).expect("Error while writing Instance profile Info part 2");
                    }
                   });
                   write_to.write_all("Instance Profile Role Tags\n\n".as_bytes()).unwrap();
                   tags.into_iter()
                   .for_each(|tag|{
                    if let (Some(key),Some(value)) = (tag.key,tag.value) {
                        let buf = format!("Key: {key} and Value: {value}\n");
                        write_to.write_all(buf.as_bytes()).expect("Error while writing Instance profile Info Part 3");
                    }

                   });

                }
            });
        }
    }
    fn write_role_policy_list(&mut self, write_to: &mut File) {
        if let Some(role_policy_lists) = self.0.role_policy_list.take() {
            write_to
                .write_all("Role Policy List\n\n".as_bytes())
                .unwrap();
            role_policy_lists.into_iter().for_each(|policy_detail| {
                if let (Some(pname), Some(pdoc)) =
                    (policy_detail.policy_name, policy_detail.policy_document)
                {
                    let decode_policy_document = decode(pdoc);
                    let buf = format!(
                        "Policy Name: {pname}\nPolicy Document: {decode_policy_document}\n"
                    );
                    write_to
                        .write_all(buf.as_bytes())
                        .expect("Error while writing role policy list\n");
                }
            });
        }
    }
    fn write_attached_managed_polices(&mut self, write_to: &mut File) {
        if let Some(managed_policies) = self.0.attached_managed_policies.take() {
            write_to
                .write_all("Attached Managed Policies\n\n".as_bytes())
                .unwrap();
            managed_policies.into_iter().for_each(|policy_detail| {
                if let (Some(pname), Some(parn)) =
                    (policy_detail.policy_name, policy_detail.policy_arn)
                {
                    let buf = format!("Policy Name: {pname}\nPolicy Arn: {parn}\n");
                    write_to
                        .write_all(buf.as_bytes())
                        .expect("Error while Writing Attached Managed Policies in A Role Detail\n");
                }
            })
        }
    }
    fn write_permissions_boundary(&mut self, write_to: &mut File) {
        if let Some(permission_boundary) = self.0.permissions_boundary.take() {
            let boundary_type = permission_boundary
                .permissions_boundary_type
                .map(|str_rep| str_rep.as_str().to_string());
            if let (Some(type_), Some(arn)) =
                (boundary_type, permission_boundary.permissions_boundary_arn)
            {
                let buf =
                    format!("Permissions Boundary\n\nPermissions Boundary Type: {type_}\nPermission Boundary Arn: {arn}\n");
                write_to
                    .write_all(buf.as_bytes())
                    .expect("Error while writing permission boundary\n");
            }
        }
    }
    fn write_role_detail_tags(&mut self, write_to: &mut File) {
        if let Some(tags) = self.0.tags.take() {
            write_to
                .write_all("Role Detail Tags\n\n".as_bytes())
                .unwrap();
            tags.into_iter().for_each(|tag| {
                if let (Some(key), Some(value)) = (tag.key, tag.value) {
                    let buf = format!("Key: {key} and Value: {value}\n");
                    write_to
                        .write_all(buf.as_bytes())
                        .expect("Error while writing Role Detail Tags\n");
                }
            });
        }
    }
    fn write_role_last_used(&mut self, write_to: &mut File) {
        if let Some(role) = self.0.role_last_used.take() {
            let date = role
                .last_used_date
                .map(|date| date.fmt(DateTimeFormat::HttpDate).ok())
                .flatten();
            if let (Some(last_used), Some(region)) = (date, role.region) {
                let buf =
                    format!("Role Usage\n\nRole Last Used: {last_used}\nRole Region: {region}\n");
                write_to
                    .write_all(buf.as_bytes())
                    .expect("Error while Writing Role Last Used\n");
            }
        }
    }
    fn write_role_detail(&mut self, write_to: &mut File) {
        if let (Some(rname), Some(rid), Some(arn), Some(path), Some(date), Some(assume_policy)) = (
            self.0.role_name.take(),
            self.0.role_id.take(),
            self.0.arn.take(),
            self.0.path.take(),
            self.create_date(),
            self.0.assume_role_policy_document.take(),
        ) {
            let decode_policy_document = decode(assume_policy);
            let buf = format!("Role Detail,data as received from https://tinyurl.com/2s979vcd\n\n\n\nRole Name: {rname}\nRole ID: {rid}\nRole Arn: {arn}\nRole Path: {path}\nRole Creation Date and Time: {date}\nAssume Role Policy Document: {decode_policy_document}\n\n");
            write_to
                .write_all(buf.as_bytes())
                .expect("Error while writing Role Detail\n");
            self.write_instance_profile_list(write_to);
            self.write_role_policy_list(write_to);
            self.write_attached_managed_polices(write_to);
            self.write_permissions_boundary(write_to);
            self.write_role_detail_tags(write_to);
            self.write_role_last_used(write_to);
        }
    }
}
pub struct WrapManagedPolicyDetail(ManagedPolicyDetail);
impl WrapManagedPolicyDetail {
    fn wrap(type_: ManagedPolicyDetail) -> Self {
        Self(type_)
    }
    fn create_date(&self) -> Option<String> {
        self.0
            .create_date()
            .map(|date| date.fmt(DateTimeFormat::HttpDate).ok())
            .flatten()
    }
    fn update_date(&self) -> Option<String> {
        self.0
            .update_date()
            .map(|date| date.fmt(DateTimeFormat::HttpDate).ok())
            .flatten()
    }
    fn write_policy_version_list(&mut self, write_to: &mut File) {
        if let Some(lists) = self.0.policy_version_list.take() {
            write_to
                .write_all("Policy Version List\n\n".as_bytes())
                .unwrap();
            lists.into_iter().for_each(|list| {
                let date = list
                    .create_date
                    .map(|date| date.fmt(DateTimeFormat::HttpDate).ok())
                    .flatten();
                if let (Some(doc), Some(vid), Some(date)) = (list.document, list.version_id, date) {
                    let decode_policy_document = decode(doc);
                    let buf = format!("Document: {decode_policy_document}\n\nVersion ID: {vid}\nIs Default Version: {}\nCreation Date and Time: {date}",list.is_default_version);
                    write_to.write_all(buf.as_bytes()).expect("Error while writing Policy Version List\n");
                }
            });
        }
    }
    fn write_managed_policy_detail(&mut self, write_to: &mut File) {
        if let (
            Some(pname),
            Some(pid),
            Some(arn),
            Some(path),
            Some(cdate),
            Some(udate),
            Some(version),
            Some(count),
            Some(boundary_count),
            is_attachable,
            Some(descrip),
        ) = (
            self.0.policy_name.take(),
            self.0.policy_id.take(),
            self.0.arn.take(),
            self.0.path.take(),
            self.create_date(),
            self.update_date(),
            self.0.default_version_id.take(),
            self.0.attachment_count,
            self.0.permissions_boundary_usage_count,
            self.0.is_attachable,
            self.0.description.take(),
        ) {
            let buf = format!("Managed Policy Detail,data as received from https://tinyurl.com/3tpcb5ej\n\n\n\nManaged Policy Name: {pname}\nManaged Policy ID: {pid}\nManaged Policy Arn: {arn}\nManaged Policy Path: {path}\nCreation Date and Time: {cdate}\nUpdate Date: {udate}\nDescription :{descrip}\nAttachment Count: {count}\nPermissions boundary usage count: {boundary_count}\nIs attachable: {is_attachable}\nDefault Version ID: {version}\n");
            write_to
                .write_all(buf.as_bytes())
                .expect("Error while writing Managed Policy Detail");
            self.write_policy_version_list(write_to);
        }
    }
}
mod pdf_writer {
    use std::collections::HashMap;

    use aws_sdk_iam::types::SummaryKeyType;
    use colored::Colorize;
    use csv::{Reader, StringRecord};
    use genpdf::{
        elements::{Break, FrameCellDecorator, Paragraph, TableLayout},
        fonts::{FontData, FontFamily},
        style::{Color, Style},
        Alignment, Document, Element, PaperSize, SimplePageDecorator,
    };
    use printpdf::types::plugins::graphics::two_dimensional::font::BuiltinFont;
    pub fn generate_credential_report_pdf(csv_data: &str) {
        let headers = vec![
            String::from("User"),
            String::from("Amazon Resource Name"),
            String::from("User Creation Date and Time"),
            String::from("Password Enabled"),
            String::from("Password Last Used"),
            String::from("Password Last Changed"),
            String::from("Password Next Rotation"),
            String::from("Multi Factor Authentication Active"),
            String::from("Access Key 1 Active"),
            String::from("Access Key 1 Last Rotated"),
            String::from("Access Key 1 Last Used Date"),
            String::from("Access Key 1 Last Used Region"),
            String::from("Access Key 1 Last Used Service"),
            String::from("Access Key 2 Active"),
            String::from("Access Key 2 Last Rotated"),
            String::from("Access Key 2 Last Used Date"),
            String::from("Access Key 2 Last Used Region"),
            String::from("Access Key 2 Last Used Service"),
            String::from("Certificate 1 Active"),
            String::from("Certificate 1 Last Used"),
            String::from("Certificate 2 Active"),
            String::from("Certificate 2 Last Used"),
        ];
        let mut csv_file = Reader::from_reader(csv_data.as_bytes());
        csv_file.set_headers(StringRecord::from(headers.clone()));

        let mut table = create_table("Keys", "Values");
        let mut iter = csv_file.into_records().skip(1);
        while let Some(record) = iter.next() {
            let record = record.unwrap();
            let records = record
                .into_iter()
                .map(|string| {
                    let mut string = string.to_string();
                    string.push(' ');
                    string
                })
                .collect::<String>();
            push_table_data_credential(&headers, records, &mut table);
            table
                .row()
                .element(Break::new(2.0))
                .element(Break::new(2.0))
                .push()
                .unwrap();
        }
        let mut document = build_document();
        document_configuration(
            &mut document,
            "Credential Report",
            "Credential Report Document",
        );
        document.push(table);
        match document.render_to_file("Credential_Report.pdf") {
            Ok(_) => println!(
                "The PDF is also generated with the name {} in the current directory\n",
                "'Credential_Report.pdf'".green().bold()
            ),
            Err(_) => println!(
                "{}\n",
                "Error while generating Credential Report 'PDF'"
                    .bright_red()
                    .bold()
            ),
        }
    }
    pub fn get_account_summary_pdf(summary_map: HashMap<SummaryKeyType, i32>) {
        let mut document = build_document();
        document_configuration(&mut document, "Account Summary", "Aws Account Summary");
        let mut table = create_table("SummaryKeyType", "Values");
        push_table_data_account_summary(summary_map, &mut table);
        document.push(table);
        match document.render_to_file("Account_Summary.pdf") {
            Ok(_) => println!(
                "The PDF is also generated with the name {} in the current directory\n",
                "'Account_Summary.pdf'".green().bold()
            ),
            Err(_) => println!(
                "{}\n",
                "Error while generating Account Summary 'PDF'"
                    .bright_red()
                    .bold()
            ),
        }
    }
    fn build_document() -> Document {
        let builtin_font = Some(BuiltinFont::HelveticaBold);
        let load_helvetica_regular = include_bytes!("./../assets/HelveticaRegular.ttf").to_vec();
        let load_helvetica_bold = include_bytes!("./../assets/HelveticaBold.ttf").to_vec();
        let load_helvetica_italic = include_bytes!("./../assets/HelveticaItalic.ttf").to_vec();
        let load_helvetica_bold_italic =
            include_bytes!("./../assets/HelveticaBoldItalic.ttf").to_vec();
        let font_data_regular = FontData::new(load_helvetica_regular, builtin_font)
            .expect("Error while getting font_bytes\n");
        let font_data_bold = FontData::new(load_helvetica_bold, builtin_font)
            .expect("Error while getting font_bytes\n");
        let font_data_italic = FontData::new(load_helvetica_italic, builtin_font)
            .expect("Error while getting font_bytes\n");
        let font_data_bold_italic = FontData::new(load_helvetica_bold_italic, builtin_font)
            .expect("Error while getting font_bytes\n");

        let font_family = FontFamily {
            regular: font_data_regular,
            bold: font_data_bold,
            italic: font_data_italic,
            bold_italic: font_data_bold_italic,
        };
        Document::new(font_family)
    }
    fn document_configuration(document: &mut Document, title: &str, page_title: &str) {
        document.set_title(title);
        document.set_minimal_conformance();
        document.set_line_spacing(1.25);
        document.push(
            Paragraph::new(page_title)
                .aligned(Alignment::Center)
                .styled(Style::new().bold()),
        );
        let mut page_decorator = SimplePageDecorator::default();
        page_decorator.set_margins(10);
        document.set_page_decorator(page_decorator);
        document.set_paper_size(PaperSize::Legal);
    }
    fn create_table(key: &str, value: &str) -> TableLayout {
        let mut table = TableLayout::new(vec![1, 1]);
        table.set_cell_decorator(FrameCellDecorator::new(true, true, false));
        let row = table.row();
        row.element(
            Paragraph::new(key)
                .aligned(Alignment::Center)
                .styled(Style::new().bold().with_color(Color::Rgb(34, 91, 247))),
        )
        .element(
            Paragraph::new(value)
                .aligned(Alignment::Center)
                .styled(Style::new().bold().with_color(Color::Rgb(208, 97, 0))),
        )
        .push()
        .unwrap();
        table
            .row()
            .element(Break::new(1.0))
            .element(Break::new(1.0))
            .push()
            .unwrap();
        table
    }

    fn push_table_data_credential(headers: &Vec<String>, records: String, table: &mut TableLayout) {
        let headers = headers.to_owned();
        for (header, record) in headers.into_iter().zip(records.split(" ")) {
            table
                .row()
                .element(
                    Paragraph::new(format!("{}", header))
                        .aligned(Alignment::Center)
                        .styled(Style::new().with_color(Color::Rgb(34, 91, 247)).bold()),
                )
                .element(
                    Paragraph::new(format!("{}", record))
                        .aligned(Alignment::Center)
                        .styled(Style::new().with_color(Color::Rgb(208, 97, 0)).bold()),
                )
                .push()
                .unwrap();
        }
    }
    fn push_table_data_account_summary(
        data: HashMap<SummaryKeyType, i32>,
        table: &mut TableLayout,
    ) {
        data.into_iter().for_each(|(key, value)| {
            let key = key.as_str();
            table
                .row()
                .element(
                    Paragraph::new(format!("{}", key))
                        .aligned(Alignment::Center)
                        .styled(Style::new().with_color(Color::Rgb(34, 91, 247)).bold()),
                )
                .element(
                    Paragraph::new(format!("{}", value))
                        .aligned(Alignment::Center)
                        .styled(Style::new().with_color(Color::Rgb(208, 97, 0)).bold()),
                )
                .push()
                .unwrap();
        });
    }
}
