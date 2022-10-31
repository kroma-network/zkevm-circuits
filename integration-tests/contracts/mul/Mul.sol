// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

contract Mul {
    function mul(uint256 num) public pure returns (uint256) {
        uint256 x = 5;
        return x * num;
    }
}
