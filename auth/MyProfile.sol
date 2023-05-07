// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

import "./Authentication.sol";

//Proteger informacion de terceros
contract Identity is Authentication {
    struct BasicInfo {
        string name;
        string email;
    }

    struct PersonalInfo {
        uint salary;
        string _address;
    }

    enum UserType {
        Basic,
        Personal
    }

    error UserUnauthorized(address user, UserType userType);
    error UserNoAuthenticated(address user);

    BasicInfo private basicInfo;
    PersonalInfo private personalInfo;
    address private owner;

    mapping(address => bool) private basicUsers;
    mapping(address => bool) private personalUsers;

    constructor(
        string memory name,
        string memory email,
        uint salary,
        string memory _address
    ) {
        basicInfo = BasicInfo(name, email);
        personalInfo = PersonalInfo(salary, _address);
        owner = msg.sender;
    }

    modifier isAuthenticated() {
        if (users[msg.sender] == true) {
            _;
        } else {
            revert UserNoAuthenticated(msg.sender);
        }
    }

    modifier authorizeUser(UserType userType) {
        if (msg.sender == owner || personalUsers[msg.sender]) {
            _;
        } else if (userType == UserType.Basic && basicUsers[msg.sender]) {
            _;
        } else {
            revert UserUnauthorized(msg.sender, userType);
        }
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can authorize users");
        _;
    }

    //Return basic info of contract owner
    function getBasicInfo()
        public
        view
        authorizeUser(UserType.Basic)
        isAuthenticated
        returns (BasicInfo memory)
    {
        return basicInfo;
    }

    //Return personal info of contract owner
    function getPersonalInfo()
        public
        view
        authorizeUser(UserType.Personal)
        isAuthenticated
        returns (PersonalInfo memory)
    {
        return personalInfo;
    }

    function registerUser(
        UserType userType,
        address user
    ) public isAuthenticated onlyOwner {
        if (userType == UserType.Basic) {
            basicUsers[user] = true;
        } else if (userType == UserType.Personal) {
            personalUsers[user] = true;
        }
    }
}
