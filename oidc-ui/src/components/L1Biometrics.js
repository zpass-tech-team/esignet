import React, { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import LoadingIndicator from "../common/LoadingIndicator";
import {
  challengeFormats,
  challengeTypes,
  configurationKeys,
} from "../constants/clientConstants";
import { LoadingStates as states } from "../constants/states";
import InputWithImage from "./InputWithImage";
import { useTranslation } from "react-i18next";
import { init, propChange } from "secure-biometric-interface-integrator";
import ErrorBanner from "../common/ErrorBanner";
import langConfigService from "../services/langConfigService";

let fieldsState = {};
const langConfig = await langConfigService.getEnLocaleConfiguration();  

export default function L1Biometrics({
  param,
  authService,
  openIDConnectService,
  backButtonDiv,
  i18nKeyPrefix1 = "l1Biometrics",
  i18nKeyPrefix2 = "errors"
}) {

  const { t: t1, i18n } = useTranslation("translation", {
    keyPrefix: i18nKeyPrefix1,
  });

  const { t: t2 } = useTranslation("translation", {
    keyPrefix: i18nKeyPrefix2,
  });

  const firstRender = useRef(true);
  const transactionId = openIDConnectService.getTransactionId();

  const inputFields = param.inputFields;

  const { post_AuthenticateUser, buildRedirectParams } = authService;

  inputFields.forEach((field) => (fieldsState["sbi_" + field.id] = ""));
  const [loginState, setLoginState] = useState(fieldsState);
  const [status, setStatus] = useState({
    state: states.LOADED,
    msg: "",
  });

  const [errorBanner, setErrorBanner] = useState(null);
  const navigate = useNavigate();

  const authTxnIdLengthValue =
    openIDConnectService.getEsignetConfiguration(
      configurationKeys.authTxnIdLength
    ) ?? process.env.REACT_APP_AUTH_TXN_ID_LENGTH;

  const authTxnIdLength = parseInt(authTxnIdLengthValue);

  const handleInputChange = (e) => {
    let { id, value } = e.target;
    let cursorPosition = e.target.selectionStart;
    if (id === 'sbi_mosip-vid') {
       // Prevent exceeding the format
        if ( value.length > 10) {
            return; // Do not update the state if the value exceeds the format
        }
        // Remove all slashes to reset the string before formatting
        value = value.replace(/[^\d]/g,"");
        // Add slashes based on the length of the value
        if (value.length > 6) {
            value = value.slice(0, 6) + '/' + value.slice(6);
            if(cursorPosition > 6) cursorPosition++;
        }
        if (value.length > 9) {
            value = value.slice(0, 9) + '/' + value.slice(9);
            if(cursorPosition > 9) cursorPosition++;
        }
        // Update the state with the formatted value
        setLoginState({ ...loginState, [id]: value }); 
        setTimeout(() => {
          e.target.setSelectionRange(cursorPosition, cursorPosition);
        }, 0);
  }
  };

  /* authenticate method after removing startCapture
   * which have capturing & authenticate as well
   */
  const authenticateBiometricResponse = async (biometricResponse) => {
    setErrorBanner(null);
    setStatus({ state: states.LOADED, msg: "" });
    const { errorCode } = validateBiometricResponse(biometricResponse);

    const vid = loginState["sbi_mosip-vid"];
    if (errorCode === null) {
      try {
        await Authenticate(
          transactionId,
          vid,
          openIDConnectService.encodeBase64(biometricResponse["biometrics"])
        );
      } catch (error) {
        setErrorBanner({
          errorCode: "authentication_failed_msg",
          show: true
        });
      }
    }
  };

  const getSBIAuthTransactionId = (oidcTransactionId) => {
    oidcTransactionId = oidcTransactionId.replace(/-/gi, "");
    oidcTransactionId = oidcTransactionId.replace(/_/gi, "");

    let transactionId = "";
    let pointer = oidcTransactionId.length;

    while (transactionId.length !== authTxnIdLength) {
      transactionId += oidcTransactionId.charAt(pointer--);
      if (pointer < 0) {
        pointer = oidcTransactionId.length;
      }
    }
    return transactionId;
  };

  /**
   *
   * @param {*} response is the SBI capture response
   * @returns first errorCode with error info, or null errorCode for no error
   */
  const validateBiometricResponse = (response) => {
    if (
      response === null ||
      response["biometrics"] === null ||
      response["biometrics"].length === 0
    ) {
      return { errorCode: "no_response_msg", defaultMsg: null };
    }

    let biometrics = response["biometrics"];

    for (let i = 0; i < biometrics.length; i++) {
      let error = biometrics[i]["error"];
      if (error !== null && error.errorCode !== "0") {
        return { errorCode: error.errorCode, defaultMsg: error.errorInfo };
      } else {
        delete biometrics[i]["error"];
      }
    }
    return { errorCode: null, defaultMsg: null };
  };

  const Authenticate = async (transactionId, uin, bioValue) => {
    const challengeList = [
      {
        authFactorType: challengeTypes.bio,
        challenge: bioValue,
        format: challengeFormats.bio,
      },
    ];

    setStatus({
      state: states.AUTHENTICATING,
      msg: "authenticating_msg",
    });

    const authenticateResponse = await post_AuthenticateUser(
      transactionId,
      uin,
      challengeList
    );

    setStatus({ state: states.LOADED, msg: "" });

    const { response, errors } = authenticateResponse;

    if (errors != null && errors.length > 0) {

      let errorCodeCondition = langConfig.errors.biometrics[errors[0].errorCode] !== undefined && langConfig.errors.biometrics[errors[0].errorCode] !== null;

      if (errorCodeCondition) {
        setErrorBanner({
          errorCode: `biometrics.${errors[0].errorCode}`,
          show: true
        });
      }
      else {
        setErrorBanner({
          errorCode: `${errors[0].errorCode}`,
          show: true
        });
      }
    } else {
      setErrorBanner(null);
      let nonce = openIDConnectService.getNonce();
      let state = openIDConnectService.getState();

      let params = buildRedirectParams(
        nonce,
        state,
        openIDConnectService.getOAuthDetails(),
        response.consentAction
      );

      navigate(process.env.PUBLIC_URL + "/consent" + params, {
        replace: true,
      });
    }
  };

  useEffect(() => {
    let mosipProp = {
      container: document.getElementById(
        "secure-biometric-interface-integration"
      ),
      buttonLabel: "scan_and_verify",
      transactionId: getSBIAuthTransactionId(transactionId),
      sbiEnv: {
        env: "Staging",
        captureTimeout: 30,
        irisBioSubtypes: "UNKNOWN",
        fingerBioSubtypes: "UNKNOWN",
        faceCaptureCount: 1,
        faceCaptureScore: 70,
        fingerCaptureCount: 1,
        fingerCaptureScore: 70,
        irisCaptureCount: 1,
        irisCaptureScore: 70,
        portRange: "4501-4512",
        discTimeout: 15,
        dinfoTimeout: 30,
        domainUri: `${window.origin}`,
      },
      langCode: i18n.language,
      disable: true,
    };

    if (firstRender.current) {
      firstRender.current = false;
      init(mosipProp);
      i18n.on("languageChanged", () => {
        propChange({ langCode: i18n.language });
      });
      return;
    }
    propChange({
      disable: !loginState["sbi_mosip-vid"].length,
      onCapture: (e) => authenticateBiometricResponse(e),
    });
  }, [loginState]);

  const onCloseHandle = () => {
    setErrorBanner(null);
  };

  return (
    <>
      <div className="grid grid-cols-8 items-center">
        {backButtonDiv}
      </div>
      {errorBanner !== null && (
        <ErrorBanner
          showBanner={errorBanner.show}
          errorCode={t2(errorBanner.errorCode)}
          onCloseHandle={onCloseHandle}
        />
      )}
      <form className="relative mt-8 space-y-5">
        <div className="-space-y-px">
          {inputFields.map((field) => (
            <InputWithImage
              key={"sbi_" + field.id}
              handleChange={handleInputChange}
              value={loginState["sbi_" + field.id]}
              labelText={t1(field.labelText)}
              labelFor={field.labelFor}
              id={"sbi_" + field.id}
              name={field.name}
              type={field.type}
              isRequired={field.isRequired}
              placeholder={t1(field.placeholder)}
              imgPath="images/photo_scan.png"
              tooltipMsg="vid_info"
            />
          ))}
        </div>
        {status.state === states.LOADING && errorBanner === null && (
          <div>
            <LoadingIndicator size="medium" message={status.msg} />
          </div>
        )}

        <div id="secure-biometric-interface-integration"></div>

        {status.state === states.AUTHENTICATING && errorBanner === null && (
          <div className="absolute bottom-0 left-0 bg-white bg-opacity-70 h-full w-full flex justify-center font-semibold">
            <div className="flex items-center">
              <LoadingIndicator
                size="medium"
                message={status.msg}
                msgParam={status.msgParam}
              />
            </div>
          </div>
        )}
      </form>
    </>
  );
}
