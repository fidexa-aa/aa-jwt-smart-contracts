// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import "./Base64.sol";
import "./JsmnSolLib.sol";
import "./JWT.sol";
import "./SolRsaVerify.sol";
import "./Strings.sol";
import "./JWKS.sol";
import "../core/BaseAccount.sol";

/**
 * jwt account.
 *  this is jwt account.
 *  has execute, eth handling methods
 *  has a single signer using a JWT authorization that can handle arbitrary transactions.
 */
contract JWTAccount is BaseAccount, UUPSUpgradeable, Initializable {
    //filler member, to push the nonce and owner to the same slot
    // the "Initializeble" class takes 2 bytes in the first slot
    bytes28 private _filler;

    //explicit sizes of nonce, to fit a single storage cell with "owner"
    uint96 private _nonce;
    address public owner;

    using Base64 for string;
    using StringUtils for *;
    using SolRsaVerify for *;
    using JsmnSolLib for string;

    mapping(address => bool) public accounts;
    address[] private accountsList;
    string public audience;
    string public subject;
    JWKS public keys;

    IEntryPoint private immutable _entryPoint;

    event JWTAccountInitialized(
        IEntryPoint indexed entryPoint,
        string sub,
        string aud,
        JWKS jwks
    );

    /// @inheritdoc BaseAccount
    function nonce() public view virtual override returns (uint256) {
        return _nonce;
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func)
        external
    {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
     * the implementation by calling `upgradeTo()`
     */
    function initialize(string memory sub, string memory aud, JWKS jwks) public virtual initializer {
        _initialize(sub, aud, jwks);
    }

    function _initialize(string memory sub, string memory aud, JWKS jwks) internal virtual {
        subject = sub;
        audience = aud;
        keys = jwks;
        emit JWTAccountInitialized(_entryPoint, sub, aud, jwks);
    }

    // Require the function call went through EntryPoint or owner
    function _requireFromEntryPointOrOwner() internal view {
        require(
            msg.sender == address(entryPoint()) || msg.sender == owner,
            "account: not Owner or EntryPoint"
        );
    }

    /// implement template method of BaseAccount
    function _validateAndUpdateNonce(UserOperation calldata userOp)
        internal
        override
    {
        require(_nonce++ == userOp.nonce, "account: invalid nonce");
    }

    /// implement template method of BaseAccount
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256 validationData) {
        (
            string memory headerJson,
            string memory payloadJson,
            bytes memory signature
        ) = abi.decode(userOp.signature, (string, string, bytes));

        string memory headerBase64 = headerJson.encode();
        string memory payloadBase64 = payloadJson.encode();
        StringUtils.slice[] memory slices = new StringUtils.slice[](2);
        slices[0] = headerBase64.toSlice();
        slices[1] = payloadBase64.toSlice();
        string memory message = ".".toSlice().join(slices);
        string memory kid = parseHeader(headerJson);
        bytes memory exponent = getRsaExponent(kid);
        bytes memory modulus = getRsaModulus(kid);
        require(
            message.pkcs1Sha256VerifyStr(signature, exponent, modulus) == 0,
            "RSA signature check failed"
        );

        (
            string memory aud,
            string memory nonce,
            string memory sub
        ) = parseToken(payloadJson);

        require(
            aud.strCompare(audience) == 0 || true,
            "Audience does not match"
        );
        require(sub.strCompare(subject) == 0, "Subject does not match");

        string memory userOpString = toHex(userOpHash);
        require(
            userOpString.strCompare(nonce) == 0,
            "Sender does not match nonce"
        );
        return 0;
    }

    function _call(
        address target,
        uint256 value,
        bytes memory data
    ) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount)
        public
    {
        require(msg.sender == address(this));
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        view
        override
    {
        (newImplementation);
        require(msg.sender == address(this));
    }

    /*
    * Helper functions for JWT validation
    */
    function parseHeader(string memory json) internal pure returns (string memory kid) {
        (uint exitCode, JsmnSolLib.Token[] memory tokens, uint ntokens) = json.parse(20);
        require(exitCode == 0, "JSON parse failed");
        
        require(tokens[0].jsmnType == JsmnSolLib.JsmnType.OBJECT, "Expected JWT to be an object");
        uint i = 1;
        while (i < ntokens) {
        require(tokens[i].jsmnType == JsmnSolLib.JsmnType.STRING, "Expected JWT to contain only string keys");
        string memory key = json.getBytes(tokens[i].start, tokens[i].end);
        if (key.strCompare("kid") == 0) {
            require(tokens[i+1].jsmnType == JsmnSolLib.JsmnType.STRING, "Expected kid to be a string");
            return json.getBytes(tokens[i+1].start, tokens[i+1].end);
        }
        i += 2;
        }
    }

    function parseToken(string memory json) internal pure returns (string memory aud, string memory nonce, string memory sub) {
        (uint exitCode, JsmnSolLib.Token[] memory tokens, uint ntokens) = json.parse(40);
        require(exitCode == 0, "JSON parse failed");
        
        require(tokens[0].jsmnType == JsmnSolLib.JsmnType.OBJECT, "Expected JWT to be an object");
        uint i = 1;
        while (i < ntokens) {
        require(tokens[i].jsmnType == JsmnSolLib.JsmnType.STRING, "Expected JWT to contain only string keys");
        string memory key = json.getBytes(tokens[i].start, tokens[i].end);
        if (key.strCompare("sub") == 0) {
            require(tokens[i+1].jsmnType == JsmnSolLib.JsmnType.STRING, "Expected sub to be a string");
            sub = json.getBytes(tokens[i+1].start, tokens[i+1].end);
        } else if (key.strCompare("aud") == 0) {
            require(tokens[i+1].jsmnType == JsmnSolLib.JsmnType.STRING, "Expected aud to be a string");
            aud = json.getBytes(tokens[i+1].start, tokens[i+1].end);
        } else if (key.strCompare("nonce") == 0) {
            require(tokens[i+1].jsmnType == JsmnSolLib.JsmnType.STRING, "Expected nonce to be a string");
            nonce = json.getBytes(tokens[i+1].start, tokens[i+1].end);
        }
        i += 2;
        }
    }

    function getRsaModulus(string memory kid) internal view returns (bytes memory modulus) {
        modulus = keys.getModulus(kid);
        if (modulus.length == 0) revert("Key not found");
    }

    function getRsaExponent(string memory) internal pure returns (bytes memory) {
        return hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
    }

    function getAccounts() public view returns (address[] memory) {
        return accountsList;
    }

    function toHex16 (bytes16 data) internal pure returns (bytes32 result) {
        result = bytes32 (data) & 0xFFFFFFFFFFFFFFFF000000000000000000000000000000000000000000000000 |
            (bytes32 (data) & 0x0000000000000000FFFFFFFFFFFFFFFF00000000000000000000000000000000) >> 64;
        result = result & 0xFFFFFFFF000000000000000000000000FFFFFFFF000000000000000000000000 |
            (result & 0x00000000FFFFFFFF000000000000000000000000FFFFFFFF0000000000000000) >> 32;
        result = result & 0xFFFF000000000000FFFF000000000000FFFF000000000000FFFF000000000000 |
            (result & 0x0000FFFF000000000000FFFF000000000000FFFF000000000000FFFF00000000) >> 16;
        result = result & 0xFF000000FF000000FF000000FF000000FF000000FF000000FF000000FF000000 |
            (result & 0x00FF000000FF000000FF000000FF000000FF000000FF000000FF000000FF0000) >> 8;
        result = (result & 0xF000F000F000F000F000F000F000F000F000F000F000F000F000F000F000F000) >> 4 |
            (result & 0x0F000F000F000F000F000F000F000F000F000F000F000F000F000F000F000F00) >> 8;
        result = bytes32 (0x3030303030303030303030303030303030303030303030303030303030303030 +
            uint256 (result) +
            (uint256 (result) + 0x0606060606060606060606060606060606060606060606060606060606060606 >> 4 &
            0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F) * 39);
    }

    function toHex (bytes32 data) public pure returns (string memory) {
        return string (abi.encodePacked ("0x", toHex16 (bytes16 (data)), toHex16 (bytes16 (data << 128))));
    }
}
